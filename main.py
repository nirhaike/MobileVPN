from src import tunnel


def main():
	listener = tunnel.VpnListener()
	listener.start()

if __name__ == "__main__":
	main()