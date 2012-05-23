#include "stdio.h"
#include <iostream>
#include <stdint.h>
#include <fstream>
#include <string>

#include "shared/silkroad_security.h"
#include "shared/stream_utility.h"

#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/filesystem.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/ini_parser.hpp>

//Handles network events
boost::asio::io_service io_service;

boost::filesystem::path executable_path();

namespace Config
{
	//Gateway server info
	std::string GatewayIP;		//Gateway server IP/hostname to connect to
	uint16_t GatewayPort;		//Gateway server port
	
	//Listen info
	std::string ListenIP;		//IP address to listen on (0.0.0.0 means every IP)
	uint16_t GatewayBind;		//Gateway server bind port
	uint16_t AgentBind;			//Agent server bind port
	uint16_t BotBind;			//The port the bot will connect to

	//Data
	uint32_t DataMaxSize;		//The maximum number of bytes to receive in one packet
};

class Network
{
private:

	//Accepts TCP connections
	boost::shared_ptr<boost::asio::ip::tcp::acceptor> acceptor;

public:

	//Constructor
	Network()
	{

	}

	//Destructor
	~Network()
	{
		Stop();
	}

	//Stops all networking objects
	void Stop()
	{
		boost::system::error_code ec;
		if(acceptor)
		{
			acceptor->close(ec);
			acceptor->cancel(ec);
		}
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
			Config::ListenIP = pt.get<std::string>("phConnector.ListenIP");
			Config::GatewayBind = pt.get<uint16_t>("phConnector.GatewayBind");
			Config::AgentBind = pt.get<uint16_t>("phConnector.AgentBind");
			Config::BotBind = pt.get<uint16_t>("phConnector.BotBind");
			Config::DataMaxSize = pt.get<uint16_t>("phConnector.DataMaxSize");
		}
		catch(std::exception & e)
		{
			//Display error and exit
			std::cout << "[Error] An error occurred while trying to retrieve settings from your config file." << std::endl;
			std::cout << e.what() << std::endl;
			std::cin.get();
			return 0;
		}
	}
	else
	{
		std::cout << "Config file does not exist. Creating one." << std::endl;

		//Create a config file, only need to save once so this part doesn't matter
		std::fstream fs(boost::filesystem::path(executable_path() / "config.ini").generic_string(), std::ios::out);
		fs << "[phConnector]\r\n";
		fs << "GatewayIP=gwgt1.joymax.com\r\n";
		fs << "GatewayPort=15779\r\n\r\n";
		fs << "ListenIP=0.0.0.0\r\n";
		fs << "GatewayBind=19000\r\n";
		fs << "AgentBind=19001\r\n";
		fs << "BotBind=19002\r\n\r\n";
		fs << "DataMaxSize=16384";
		fs.close();

		//Exit
		std::cout << "Config file has been created. Please restart phConnector." << std::endl;
		std::cin.get();
		return 0;
	}

	//Let the user know which ports to connect to
	std::cout << "Redirect Silkroad to 127.0.0.1:" << Config::GatewayBind << std::endl;
	std::cout << "Redirect the bot to 127.0.0.1:" << Config::BotBind << std::endl;

	//Start processing network events
	boost::system::error_code ec;
	io_service.run(ec);

	//Display error message if there was one
	if(ec) std::cout << "[Error] " << ec.message() << std::endl;

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
		readlink("/proc/self/exe", temp, sizeof(temp));

		std::string str(temp);
		str.erase(str.begin() + str.find_last_of("/"), str.end());
		executable_path_final = boost::filesystem::path(str);
#endif
	}

	return executable_path_final;
}