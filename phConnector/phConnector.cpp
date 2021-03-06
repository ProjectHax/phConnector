#include "stdio.h"
#include <iostream>
#include <stdint.h>
#include <fstream>
#include <string>
#include <list>

#include "shared/silkroad_security.h"
#include "shared/stream_utility.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/make_shared.hpp>
#include <boost/filesystem.hpp>
#include <boost/function.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/unordered_map.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

//Handles network events
boost::asio::io_service io_service;

//Agent server info
std::string AgentIP;
uint16_t AgentPort = 0;
bool AgentConnect = false;

//Timer delay for processing packets
#define PACKET_PROCESS_DELAY 10

boost::filesystem::path executable_path();

//Inject functions
boost::function<void(uint16_t opcode, StreamUtility & p, bool encrypted)> InjectJoymax;
boost::function<void(uint16_t opcode, StreamUtility & p, bool encrypted)> InjectSilkroad;

//Blocked opcode list
boost::unordered_map<uint16_t, bool> BlockedOpcodes;

namespace Config
{
	//Gateway server info
	std::string GatewayIP;		//Gateway server IP/hostname to connect to
	uint16_t GatewayPort;		//Gateway server port
	
	//Listen info
	uint16_t BindPort;			//Gateway server bind port
	uint16_t BotBind;			//The port the bot will connect to

	//Data
	uint32_t DataMaxSize;		//The maximum number of bytes to receive in one packet
};

class BotConnection
{
private:

	struct BotData
	{
		std::vector<uint8_t> data;
		StreamUtility pending_stream;

		BotData()
		{
			data.resize(Config::DataMaxSize + 1);
		}
	};

	//Accepts TCP connections
	boost::asio::ip::tcp::acceptor acceptor;

	//Connections
	std::map<boost::shared_ptr<boost::asio::ip::tcp::socket>, boost::shared_ptr<BotData> > sockets;

	//Starts accepting new connections
	void PostAccept(uint32_t count = 1)
	{
		for(uint32_t x = 0; x < count; ++x)
		{
			//The newly created socket will be used when something connects
			boost::shared_ptr<boost::asio::ip::tcp::socket> s(boost::make_shared<boost::asio::ip::tcp::socket>(io_service));
			acceptor.async_accept(*s, boost::bind(&BotConnection::HandleAccept, this, s, boost::asio::placeholders::error));
		}
	}

	//Handles new connections
	void HandleAccept(boost::shared_ptr<boost::asio::ip::tcp::socket> s, const boost::system::error_code & error)
	{
		//Error check
		if(!error)
		{
			std::cout << "Bot/Analyzer connected" << std::endl;

			//Disable nagle
			s->set_option(boost::asio::ip::tcp::no_delay(true));

			//Add the connection to the list
			boost::shared_ptr<BotData> temp = boost::make_shared<BotData>();
			sockets[s] = temp;

			s->async_read_some(boost::asio::buffer(&temp->data[0], Config::DataMaxSize), boost::bind(&BotConnection::HandleRead, this, s, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));

			//Post another accept
			PostAccept();
		}
	}

	//Handles incoming packets
	void HandleRead(boost::shared_ptr<boost::asio::ip::tcp::socket> s, size_t bytes_transferred, const boost::system::error_code & error)
	{
		std::map<boost::shared_ptr<boost::asio::ip::tcp::socket>, boost::shared_ptr<BotData> >::iterator itr = sockets.find(s);
		if(itr != sockets.end())
		{
			if(error)
			{
				if(s)
				{
					//Shutdown and close the connection
					boost::system::error_code ec;
					s->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
					s->close(ec);
				}

				//Remove the socket from the list
				sockets.erase(s);
			}
			else
			{
				//Extract structure objects
				std::vector<uint8_t> & data = itr->second->data;
				StreamUtility & pending_stream = itr->second->pending_stream;

				//Write the received data to the end of the stream
				pending_stream.Write<uint8_t>(&data[0], bytes_transferred);

				//Total size of stream
				int32_t total_bytes = pending_stream.GetStreamSize();

				//Make sure there are enough bytes for the packet size to be read
				while(total_bytes > 2)
				{
					//Peek the packet size
					uint16_t required_size = pending_stream.Read<uint16_t>(true) + 6;

					//See if there are enough bytes for this packet
					if(required_size <= total_bytes)
					{
						StreamUtility r(pending_stream);

						//Remove this packet from the stream
						pending_stream.Delete(0, required_size);
						pending_stream.SeekRead(0, Seek_Set);
						total_bytes -= required_size;

						uint16_t size = r.Read<uint16_t>();
						uint16_t opcode = r.Read<uint16_t>();
						uint8_t direction = r.Read<uint8_t>();
						r.Read<uint8_t>();

						//Remove the header
						r.Delete(0, 6);
						r.SeekRead(0, Seek_Set);

						if(opcode == 1 || opcode == 2)
						{
							uint16_t real_opcode = r.Read<uint16_t>();

							//Block opcode
							if(opcode == 1)
							{
								BlockedOpcodes[real_opcode] = true;
								std::cout << "Opcode [0x" << std::hex << std::setfill('0') << std::setw(4) << real_opcode << "] has been blocked" << std::endl << std::dec;
							}
							//Remove blocked opcode
							else if(opcode == 2)
							{
								boost::unordered_map<uint16_t, bool>::iterator itr = BlockedOpcodes.find(real_opcode);
								if(itr != BlockedOpcodes.end())
								{
									BlockedOpcodes.erase(itr);
									std::cout << "Opcode [0x" << std::hex << std::setfill('0') << std::setw(4) << real_opcode << "] has been unblocked" << std::endl << std::dec;
								}
							}
						}
						else
						{
							//Silkroad
							if(direction == 2 || direction == 4)
							{
								InjectSilkroad(opcode, r, direction == 4 ? true : false);
							}
							//Joymax
							else if(direction == 1 || direction == 3)
							{
								InjectJoymax(opcode, r, direction == 3 ? true : false);
							}
						}
					}
					else
					{
						//Not enough bytes received for this packet
						break;
					}
				}

				//Read more data
				s->async_read_some(boost::asio::buffer(&data[0], Config::DataMaxSize), boost::bind(&BotConnection::HandleRead, this, s, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
			}
		}
	}

public:

	//Constructor
	BotConnection(uint16_t port) : acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port))
	{
		PostAccept();
	}

	//Destructor
	~BotConnection()
	{
	}

	//Sends packets to all connections
	void Send(PacketContainer & container, uint8_t direction)
	{
		StreamUtility & r = container.data;

		StreamUtility w;
		w.Write<uint16_t>(r.GetReadStreamSize());
		w.Write<uint16_t>(container.opcode);
		w.Write<uint8_t>(direction);
		w.Write<uint8_t>(container.encrypted);
		
		while(r.GetReadStreamSize())
			w.Write<uint8_t>(r.Read<uint8_t>());

		//Reset the read index
		r.SeekRead(0, Seek_Set);

		//Iterate all connections
		std::map<boost::shared_ptr<boost::asio::ip::tcp::socket>, boost::shared_ptr<BotData> >::iterator itr = sockets.begin();
		while(itr != sockets.end())
		{
			//Send the packet
			boost::system::error_code ec;
			boost::asio::write(*itr->first, boost::asio::buffer(w.GetStreamPtr(), w.GetStreamSize()), boost::asio::transfer_all(), ec);
			
			//Next
			++itr;
		}
	}

	void Stop()
	{
		boost::system::error_code ec;

		//Iterate all connections
		std::map<boost::shared_ptr<boost::asio::ip::tcp::socket>, boost::shared_ptr<BotData> >::iterator itr = sockets.begin();
		while(itr != sockets.end())
		{
			//Shutdown and close the connection
			itr->first->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			itr->first->close(ec);

			//Next
			++itr;
		}

		sockets.clear();
	}
};

//Has to be created after the settings are loaded
boost::shared_ptr<BotConnection> Bot;

//Silkroad connection class
class SilkroadConnection
{
private:

	//Socket
	boost::shared_ptr<boost::asio::ip::tcp::socket> s;

	//Data
	std::vector<uint8_t> data;

	//Handles incoming packets
	void HandleRead(size_t bytes_transferred, const boost::system::error_code & error)
	{
		if(!error && s && security)
		{
			security->Recv(&data[0], bytes_transferred);
			PostRead();
		}
	}

public:

	//Security
	boost::shared_ptr<SilkroadSecurity> security;

	//Constructor
	SilkroadConnection()
	{
		data.resize(Config::DataMaxSize + 1);
	}

	//Destructor
	~SilkroadConnection()
	{
		Close();
	}

	//Gets everything ready for receiving packets
	void Initialize(boost::shared_ptr<boost::asio::ip::tcp::socket> s_)
	{
		s = s_;
		security = boost::make_shared<SilkroadSecurity>();
	}

	//Starts receiving data
	void PostRead()
	{
		if(s && security)
		{
			s->async_read_some(boost::asio::buffer(&data[0], Config::DataMaxSize), boost::bind(&SilkroadConnection::HandleRead, this, boost::asio::placeholders::bytes_transferred, boost::asio::placeholders::error));
		}
	}

	//Closes the socket
	void Close()
	{
		if(s)
		{
			boost::system::error_code ec;
			s->shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
			s->close(ec);
			s.reset();
		}

		security.reset();
	}

	boost::system::error_code Connect(const std::string & IP, uint16_t port)
	{
		//Create the socket
		s = boost::make_shared<boost::asio::ip::tcp::socket>(io_service);

		boost::system::error_code ec;
		boost::system::error_code resolve_ec;

		for(uint8_t x = 0; x < 3; ++x)
		{
			//Connect
			s->connect(boost::asio::ip::tcp::endpoint(boost::asio::ip::address::from_string(IP, resolve_ec), port), ec);

			//Probably not a valid IP so it's a hostname
			if(resolve_ec)
			{
				boost::asio::ip::tcp::resolver resolver(io_service);
				boost::asio::ip::tcp::resolver::query query(boost::asio::ip::tcp::v4(), IP, boost::lexical_cast<std::string>(port));
				boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);
				s->connect(*iterator, ec);
			}

			//See if there was an error
			if(!ec) break;

			//Error occurred so wait
			boost::this_thread::sleep(boost::posix_time::milliseconds(500));
		}

		if(!ec)
		{
			//Create new Silkroad security
			security = boost::make_shared<SilkroadSecurity>();

			//Disable nagle
			s->set_option(boost::asio::ip::tcp::no_delay(true));
		}

		return ec;
	}

	//Hands packets off to the security API
	bool Inject(uint16_t opcode, StreamUtility & p, bool encrypted = false)
	{
		if(security)
		{
			security->Send(opcode, p, encrypted ? 1 : 0, 0);
			return true;
		}

		return false;
	}

	//Hands packets off to the security API
	bool Inject(uint16_t opcode, bool encrypted = false)
	{
		if(security)
		{
			security->Send(opcode, 0, 0, encrypted ? 1 : 0, 0);
			return true;
		}

		return false;
	}

	//Hands packets off to the security API
	bool Inject(PacketContainer & container)
	{
		if(security)
		{
			security->Send(container.opcode, container.data, container.encrypted, container.massive);
			return true;
		}

		return false;
	}

	//Sends a formatted packet
	bool Send(const std::vector<uint8_t> & packet)
	{
		if(!s) return false;

		//Send the packet all at once
		boost::system::error_code ec;
		boost::asio::write(*s, boost::asio::buffer(&packet[0], packet.size()), boost::asio::transfer_all(), ec);
		
		//See if there was an error
		if(ec)
		{
			Close();
			return false;
		}

		return true;
	}
};

//Networking class (handles connections)
class Network
{
private:

	//Accepts TCP connections
	boost::asio::ip::tcp::acceptor acceptor;

	//Packet processing timer
	boost::shared_ptr<boost::asio::deadline_timer> timer;

	//Silkroad connections
	SilkroadConnection Silkroad;
	SilkroadConnection Joymax;

	//Starts accepting new connections
	void PostAccept(uint32_t count = 1)
	{
		for(uint32_t x = 0; x < count; ++x)
		{
			//The newly created socket will be used when something connects
			boost::shared_ptr<boost::asio::ip::tcp::socket> s(boost::make_shared<boost::asio::ip::tcp::socket>(io_service));
			acceptor.async_accept(*s, boost::bind(&Network::HandleAccept, this, s, boost::asio::placeholders::error));
		}
	}
	
	//Handles new connections
	void HandleAccept(boost::shared_ptr<boost::asio::ip::tcp::socket> s, const boost::system::error_code & error)
	{
		//Error check
		if(!error)
		{
			//Close active connections
			Silkroad.Close();
			Joymax.Close();

			//Disable nagle
			s->set_option(boost::asio::ip::tcp::no_delay(true));

			Silkroad.Initialize(s);
			Silkroad.security->GenerateHandshake();

			//Connect to the gateway server
			std::cout << "Connecting to " << (AgentConnect ? AgentIP : Config::GatewayIP) << ":" << (AgentConnect ? AgentPort : Config::GatewayPort) << std::endl;
			boost::system::error_code ec = Joymax.Connect(AgentConnect ? AgentIP : Config::GatewayIP, AgentConnect ? AgentPort : Config::GatewayPort);

			//Error check
			if(ec)
			{
				std::cout << "[Error] Unable to connect to " << (AgentConnect ? AgentIP : Config::GatewayIP) << ":" << (AgentConnect ? AgentPort : Config::GatewayPort) << std::endl;
				std::cout << ec.message() << std::endl;

				//Silkroad connection is no longer needed
				Silkroad.Close();
			}
			else
			{
				Silkroad.PostRead();
				Joymax.PostRead();
			}

			//Next connection goes to the gateway server
			AgentConnect = false;

			//Post another accept
			PostAccept();
		}
	}

	void ProcessPackets(const boost::system::error_code & error)
	{
		if(!error)
		{
			if(Silkroad.security)
			{
				while(Silkroad.security->HasPacketToRecv())
				{
					bool forward = true;

					//Retrieve the packet out of the security api
					PacketContainer p = Silkroad.security->GetPacketToRecv();

					//Check the blocked list
					if(BlockedOpcodes.find(p.opcode) != BlockedOpcodes.end())
						forward = false;

					if(p.opcode == 0x2001)
					{
						std::cout << "Connected" << std::endl;
						forward = false;
					}

					//Forward the packet to Joymax
					if(forward && Joymax.security)
					{
						Bot->Send(p, 1);
						Joymax.Inject(p);
					}
				}

				//Send packets that are currently in the security api
				while(Silkroad.security->HasPacketToSend())
				{
					if(!Silkroad.Send(Silkroad.security->GetPacketToSend()))
						break;
				}
			}

			if(Joymax.security)
			{
				while(Joymax.security->HasPacketToRecv())
				{
					bool forward = true;

					//Retrieve the packet out of the security api
					PacketContainer p = Joymax.security->GetPacketToRecv();

					//Check the blocked list
					if(BlockedOpcodes.find(p.opcode) != BlockedOpcodes.end())
						forward = false;

					if(p.opcode == 0xA102)
					{
						StreamUtility & r = p.data;
						if(r.Read<uint8_t>() == 1)
						{
							//Do not forward the packet to Joymax, we need to replace the agent server data
							forward = false;
							
							//The next connection will go to the agent server
							AgentConnect = true;

							uint32_t LoginID = r.Read<uint32_t>();				//Login ID
							AgentIP = r.Read_Ascii(r.Read<uint16_t>());			//Agent IP
							AgentPort = r.Read<uint16_t>();						//Agent port

							StreamUtility w;
							w.Write<uint8_t>(1);								//Success flag
							w.Write<uint32_t>(LoginID);							//Login ID
							w.Write<uint16_t>(9);								//Length of 127.0.0.1
							w.Write_Ascii("127.0.0.1");							//IP
							w.Write<uint16_t>(Config::BindPort);				//Port

							//Inject the packet
							Silkroad.Inject(p.opcode, w);

							//Inject the packet immediately
							while(Silkroad.security->HasPacketToSend())
								Silkroad.Send(Silkroad.security->GetPacketToSend());

							//Close active connections
							Silkroad.Close();
							Joymax.Close();

							//Security pointer is now valid so skip to the end
							goto Post;
						}
					}

					//Forward the packet to Silkroad
					if(forward && Silkroad.security)
					{
						Bot->Send(p, 0);
						Silkroad.Inject(p);
					}
				}

				//Send packets that are currently in the security api
				while(Joymax.security->HasPacketToSend())
				{
					if(!Joymax.Send(Joymax.security->GetPacketToSend()))
						break;
				}
			}

Post:
			//Repost the timer
			timer->expires_from_now(boost::posix_time::milliseconds(PACKET_PROCESS_DELAY));
			timer->async_wait(boost::bind(&Network::ProcessPackets, this, boost::asio::placeholders::error));
		}
	}

public:

	//Constructor
	Network(uint16_t port) : acceptor(io_service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
		timer(boost::make_shared<boost::asio::deadline_timer>(io_service))
	{
		//Bind inject functions
		InjectJoymax = boost::bind(&SilkroadConnection::Inject, &Joymax, _1, _2, _3);
		InjectSilkroad = boost::bind(&SilkroadConnection::Inject, &Silkroad, _1, _2, _3);

		//Start accepting connections
		PostAccept();

		//Post the packet processing timer
		timer->expires_from_now(boost::posix_time::milliseconds(PACKET_PROCESS_DELAY));
		timer->async_wait(boost::bind(&Network::ProcessPackets, this, boost::asio::placeholders::error));
	}

	//Destructor
	~Network()
	{
		//Stop everything (shutting down)
		Stop();
	}

	//Stops all networking objects
	void Stop()
	{
		boost::system::error_code ec;
		acceptor.close(ec);
		acceptor.cancel(ec);

		if(timer)
			timer->cancel(ec);

		Silkroad.Close();
		Joymax.Close();
	}
};

int main(int argc, char* argv[])
{
	std::cout << "phConnector Open Source" << std::endl;
	std::cout << "Visit ProjectHax.com or github.com/projecthax to see our other releases." << std::endl << std::endl;

	std::ifstream ifs(boost::filesystem::path(executable_path() / "config.ini").generic_string(), std::ios::in);

	//Open check
	if(ifs.is_open())
	{
		//Parse the config file
		boost::property_tree::ptree pt;
		boost::property_tree::ini_parser::read_ini(ifs, pt);

		//Close the file
		ifs.close();

		//Attempt to read the values, if an error occurs the node name will be displayed
		try
		{
			Config::GatewayIP = pt.get<std::string>("phConnector.GatewayIP");
			Config::GatewayPort = pt.get<uint16_t>("phConnector.GatewayPort");
			Config::BindPort = pt.get<uint16_t>("phConnector.BindPort");
			Config::BotBind = pt.get<uint16_t>("phConnector.BotBind");
			Config::DataMaxSize = pt.get<uint32_t>("phConnector.DataMaxSize");
		}
		catch(std::exception & e)
		{
			//Display error and exit
			std::cout << "[Fatal Error] An error occurred while trying to retrieve settings from your config file." << std::endl;
			std::cout << e.what() << std::endl;
			std::cin.get();
			return 0;
		}
	}
	else
	{
		std::cout << "[Error] Config file does not exist. Creating one." << std::endl;

		//Create a config file, only need to save once so this part doesn't matter
		std::fstream fs(boost::filesystem::path(executable_path() / "config.ini").generic_string(), std::ios::out);
		fs << "[phConnector]\n";
		fs << "GatewayIP=gwgt1.joymax.com\n";		//iSRO gateway server
		fs << "GatewayPort=15779\n";				//iSRO gateway port
		fs << "BindPort=15779\n";					//The port phConnector will listen on
		fs << "BotBind=22580\n";					//The port the bot or analyzer will connect to
		fs << "DataMaxSize=16384";					//Maximum number of bytes to receive in one packet
		fs.close();

		//Exit
		std::cout << "Config file has been created. Please restart phConnector." << std::endl;
		std::cin.get();
		return 0;
	}

	//Let the user know which ports to connect to
	std::cout << "Redirect Silkroad to 127.0.0.1:" << Config::BindPort << std::endl;
	std::cout << "Redirect the bot to 127.0.0.1:" << Config::BotBind << std::endl << std::endl;

	//Create the network objects
	Network network(Config::BindPort);
	Bot = boost::make_shared<BotConnection>(Config::BotBind);

	//Start processing network events
	while(true)
	{
		try
		{
			//Run
			boost::system::error_code ec;
			io_service.run(ec);

			if(ec)
			{
				std::cout << "[" << __FUNCTION__ << "]" << "[" << __LINE__ << "] " << ec.message() << std::endl;
			}
			else
			{
				//No more work
				break;
			}
			
			//Prevent high CPU usage
			boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
		catch(std::exception & e)
		{
			std::cout << "[" << __FUNCTION__ << "]" << "[" << __LINE__ << "] " << e.what() << std::endl;
		}
	}

	//Cleanup
	network.Stop();
	Bot->Stop();
	Bot.reset();

	return 0;
}

//Simple function I created to get the path of the current executable (works on Linux too)
boost::filesystem::path executable_path()
{
	static boost::filesystem::path executable_path_final;

	if(executable_path_final.empty())
	{
#ifdef _WIN32
		wchar_t temp[2048] = {0};
		GetModuleFileNameW(GetModuleHandle(0), temp, 2047);

		std::wstring str(temp);
		str.erase(str.begin() + str.find_last_of(L"\\"), str.end());
		executable_path_final = boost::filesystem::path(str);
#else
		char temp[2048] = {0};
		if(readlink("/proc/self/exe", temp, sizeof(temp)))
		{
			std::string str(temp);
			str.erase(str.begin() + str.find_last_of("/"), str.end());
			executable_path_final = boost::filesystem::path(str);
		}
#endif
	}

	return executable_path_final;
}