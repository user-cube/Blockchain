#!/bin/bash

function run()
{
	xterm -T "Auction Repository" -hold -e "source ../venv/bin/activate && python3 auction_Repository/server.py" &
	sleep 3
	xterm -T "Auction Manager" -hold -e "source ../venv/bin/activate && python3 auction_Manager/server.py" &
	sleep 3
	xterm -T "Auction Client" -hold -e "source ../venv/bin/activate && python3 auction_Client/client.py" &
	sleep 3
}

function killXterm()
{
	killall xterm
}

function menu()
{
	read -p "Kill [Y/N]? " decision

	case $decision in
		Y)
			killXterm
			exit
			;;
		y)	
			killXterm
			exit
			;;
		*)
			menu
			;;
	esac
}

trap "killXterm ; exit 0" SIGINT
run
menu
