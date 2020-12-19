# Packet Filterting
> The Packet Analizer was developed as the final project, of Traffic Monitoring analisis Subject of the Mater on Cybersecurity at UPC

## Installing

## Requirements
The requirements versions defined below, are the ones used to develop the project:
* GCC 9.3.0
* Pcap library
* Node v12.18.4
* Make v4.2.1

## Execution
To execute the code, it's need it a .cap file, and pass the path to the program on the command line:

```
./PacketFilter <pcap_file>
```
The program will start analising the file and writing the output to the data folder.

After the program execution, run the node.js server to print the data with a beatiful chart on your browser:

```
node server.js
```

Now open the webbrowser and navigate [localhost:8080](http://127.0.0.1:8080).


## License
The GNU General Public License v3.0. Please see [LICENSE](https://github.com/TMASmartFirewall/packet_filtering/blob/main/LICENSE.md) for more information.

## Contributors
@[Marti Miquel](https://github.com/MartiMiquel) \
@[Èric Monné](https://github.com/orgs/TMASmartFirewall/people/xemyst) \
@[Waleed](https://github.com/ias20) \
@Marc Muro Barbe
