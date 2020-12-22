# Packet Filterting
> The Packet Analizer was developed as the final project, of Traffic Monitoring analisis Subject of the Mater on Cybersecurity at UPC

On this repository you will find the Packet Filtering project. This project is focused on the analysing of .cap files, to find the DNS and HTTP requests to determinate where the user is connecting.

The software consists in two steps, the first one is the filtering process, which will read the .cap file and write a JSON with the found it data. After this process a web server can be opened to see the chart with the data obtained.

To obtain the full power of this project, it's better to use it with [packet action](https://github.com/TMASmartFirewall/packet_action). The idea is to use this repo as analyzer, and after to obtain the results, take an action with packet action.

## Requirements
The requirements versions defined below, are the ones used to develop the project:
* GCC 9.3.0
* Pcap library
* Node v12.18.4
* Make v4.2.1

## Installing

To install this project you just need to run the make file.
```
make
```

## Execution
To execute the code, it's need it a .cap file, and pass the path to the program on the command line:

```
./PacketFilter <pcap_file>
```
The program will start analising the file and writing the output to the data folder.

After the program execution, run the node.js server to print the data with a beatiful chart on your browser:

```
npm install
node index.js
```

Now open the webbrowser and navigate [localhost:8080](http://127.0.0.1:8080).


## License
The GNU General Public License v3.0. Please see [LICENSE](https://github.com/TMASmartFirewall/packet_filtering/blob/main/LICENSE.md) for more information.

## Contributors
@[Marti Miquel](https://github.com/MartiMiquel) \
@[Èric Monné](https://github.com/orgs/TMASmartFirewall/people/xemyst) \
@[Waleed](https://github.com/ias20) \
@Marc Muro Barbe
