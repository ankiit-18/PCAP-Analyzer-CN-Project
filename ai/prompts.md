# AI usage: prompts

**Tool:** Claude (Anthropic) through the Claude desktop app (Claude Code), model Sonnet 5.5.
Prompts below are the team's own messages (quoted as written, long ones shortened with "…"). Claude's replies are summarised, not copied; a full chat export can be added to this folder.

| # | Prompt (team) | What Claude produced |
|---|---|---|
| 1 | "This is my CN project and right now we have to focus on building backend engine for pcap analysis, so first create a google collab notebook where i will upload a pcap file and it will show all the ananlysis data as mentioned in the project description pdf" | First Colab notebook (Scapy-based) and a written explanation of every calculation. |
| 2 | "since we have a backend running tshark commands … for all the stats which can be obtained through tshark use tshark commands, and for the stats which don't have any tshark command for now just report it" | Notebook rebuilt on TShark; list of statistics TShark cannot provide. |
| 3 | "i am not aware of capinfos, use only tshark commands as said, and report the stats that can't be obtained from Wireshark, update the notebook" | capinfos removed; whole-capture totals via `tshark -z io,stat,0`. |
| 4 | "Keep in the core version: PCAP/PCAPNG upload and validation. Packet parsing and TCP flow identification. RTT samples and per-flow RTT. Retransmissions, duplicate ACKs, out-of-order and sequence-gap indicators. … JUST DO THESE IN notebook for 1st stage" | Stage-1 core notebook and `tshark_core.py`. |
| 5 | "now core engine is ready now lets move to final dashboard making use react js for frontend and other suitable librabries for charts display and python backend you can use fast api, the dashboard should have an option of upload pcap file once done it should show analyze button …" | FastAPI backend, React + ECharts dashboard, run scripts, README. |
| 6 | "2. Product and frontend structure: overview first, detail on click … implement these changes, don't mess existing one" | Overview page, protocol cards, detail pages, packet decode, UDP/DNS/TLS/HTTP/ICMP/DHCP/RTP analyzers. |
| 7 | "look into this pdf and tell me whatever is left to build just state it dont build or code anything" then "so build whatever is left and dont make mess" | Gap analysis, then the `engine` package, TCP flow control / congestion / options, IP page, limits, cross-validation, notebooks, 47+ tests. |
| 8 | "In the overview page i want info about all the protocols … a detailed page should be available only for TCP, UDP, DNS, TLS, QUIC, ARP" | Overview lists every protocol; detail pages restricted to the six protocols (+ IP). |
| 9 | "so remove limits no need for them and just let me know how big file can it handle now a number" | Limits switched off by default; measured time and memory at five sizes. |
| 10 | UI clean-up prompts: remove explanatory text, the tshark command list, the time-sequence/RTT graphs, selected metrics and charts | Corresponding removals; tests updated. |
| 11 | "I have changed the location for the project and its name to code … can u make required changes for running the code correctly" | Move-proof `start.sh` / `start.bat`. |
| 12 | "give final editable docs file in same format as shown in pdf, and write accurately, limit is 10 pages and strictly follow mentioned conditions" | `report/Final_Project_Report.docx` (this report), figures and tables from measured results. |

Debugging examples where AI helped: ICMP error messages embedding TCP/UDP headers were counted as TCP/UDP (found by the cross-validation harness); TShark field availability differences; `dns.response_in` needing two-pass mode; broken virtual environment after moving the folder.
