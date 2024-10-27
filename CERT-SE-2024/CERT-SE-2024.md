# CERT-SE-2024 CTF

This CTF was hosted by CERT-SE (MSB) in October 2024. It is available at the following link: https://www.cert.se/2024/09/cert-se-ctf2024.html.

From the description we have:

```
<scenario>
A fictional organisation has been affected by a ransomware attack. It has been successful in setting up an emergency channel for communication and has access to parts of its infrastructure.

Can you find all the flags?
</scenario>
```

There are a total of 9 flags, eight having the format "CTF[FLAG]" and one just in the format "[FLAG]", appending CTF gives you the full flag.

The following tools and programs was mainly used to complete the challenge:

- Wireshark / tshark
- Autopsy (not needed)
- Cyberchef
- ...

## CERT-SE_CTF2024.pcap

Extracting the initial .zip file we are greated with a pcap file. We open this into wireshark to start analyzing it and looking for clues.

Going through the protocol hierarchy we can see that there appears the be an IRC conversation in place along with that files being transfered using FTP:

![Protocol statistics](images/protocol_hierarchy_1.png)

Lets start by looking over the IRC conversation for any interesting hints.

### IRC

By following the TCP-stream that corresponds to the IRC conversation we can easily examine the entire conversation.

From the IRC conversation we can conclude the following:

- Two users are in the #emergency chanel, that being An4lys3r! and D3f3nd3r.
- The ransomware note has been found on the infected system and sent over IRC as `RANSOM_NOTE.gz`.
- There was two `.pcap` files uploaded to the FTP server containing captured traffic from weeks / days before the attack happend.
- There is one disk file being discused that is also uploaded to the FTP server from one of their clients
- A wordlist was able to be recovered that was created by scraping their public website. It is also uploaded to the FTP server
- Two helping indicators for who was behind the attack was given.
  - First that traffic recorded from a windows workstation `CTF-PC01` was being discused on a closed forum.
  - Second, the ip-address `195.200.72.82` was involved in C2 and exfiltration activities

This gives us plenty of leads to follow and analyze. Before we continue, in the IRC conversation the first two flags can be found.

The first one can be found at the very start of the IRC conversations TCP-stream, that being `CTF[AES128]`:

![FLAG 1](images/flag1.png)

Continuing down the conversation we can see a message discussing a "strange string" that their were handed by someone at allsafe. This is the second flag `CTF[E65D46AD10F92508F500944B53168930]`:

![FLAG 2](images/flag2.png)

With the two flags out of the way lets starts extracting the different files from the traffic.

We start of with the ransom note sent over IRC. To begin we find the packet were it began transfering in the IRC conersation, that being packet nr 157. Going a few packets down we can see a large amount of just pure TCP packets. By following this stream and viewing it in hex, we can see that the first hex characters, `1f 8b`, match the magic bytes for a gzip:

![Hex](images/gz_bytes.png)

To save this, we simply show the data in the "RAW" format (binary) and save the file as `RANSOM_NOTE.gz`.

With that, we have gotten everything from the IRC conversation and can move on to analyze the FTP protocol.

### FTP

We know that atleast 3-4 four files have been uploaded to a FTP server, so lets get them.

By following the TCP streams in Wireshark and incremanting through them we eventually get to the first one, displaying FTP commands:

![FTP stream](images/ftp_stream.png)

At the bottom of the stream we can see the name of the file being uploaded (in this case "corp_net1.pcap") and that it was sucsefully transfered. Looking at the next TCP stream (nr 4) in hex view, we can see that the first hex characters, `d4 c3`, matches that of the magic bytes of a .pcap files. This indicates that this is the file uploaded:

![PCAP bytes](images/pcap_bytes.png)

To extract it we do the same method as we did with the ransome note (view as RAW and save as with the corresponding extension).

Navigating through all the remaining TCP streams related to FTP and repating the same method as show above we end up with the following files:

- corp_net1.pcap
- corp_net2.pcap
- disk.img.gz
- WORDLIST.txt

For clarities sake the WORDLIST.txt file contains strings in the following format `[STRING]`, the exact same as one of the flags:

![alt text](images/WORDLIST.png)

This is most likley going to be used in the future to get the correct flag from this file.

With that we have extracted everything of note and completed the analysis of the initial file. The remaining file can be tackled in any order.

## RANSOM_NOTE.gz

To start of we extract the archive to get the contents, inside we can find a single file namned "why_not". Openining it in a text editor gives the following:

![alt text](images/ransom_note.png)

Quickly looking over it we can see a lot of the following character: "C", "T", "F", "O", "R" and "\["; further all these characters have the exact same number of occurences. This is most likley an attempt to obfuscate the flag. Searching for "\]" in the files gives us 1 matched character! By either going backwards from this character until the format is correct OR removing all occurnces of characters except the first will give us our third flag, `CTF[OR]`:

![alt text](images/flag3.png)

## disk.img.gz - Part 1

After extracting the .img file we open it in any analysis tool (or mount it). In this example "Autopsy" was used, mainly because I have used it before and had it ready.

After autopsy finishes analyzing the file we can look into the FAT32 file system extracted and note the following files:

![alt text](images/disk.png)

There are a couple out of the ordinary files here:

- secret.encrypted
- ranswomare.sh
- secret
- sslkeylogfile

Lets start by looking at the `ransomware.sh` file that has been deleted.

### Ransomware.sh

Opening it in autopsy we can see a short bash script that appears to have been executed:

![ransomware](images/ransomware.png)

Lets do a quick walkthrough of what it does:

- Starts by declaring the `password` variable
- Sets the content of the local variable `SSLKEYLOGFILE` to the content of the file `sslkeylogfile`
- Sets the password variable to the content of the `https://whatyoulookingat.com/1.txt` file from the cURL request.
- Encrypts the `secret`files using AES-128-CBC with the password gotten from the previous step and saves it to `secret.encrypted`.
- Finally it overwrites the original `secret`file, before deleting it along with `sslkeylogfile` and finally itself.

Looking at the `secret` file we can see that it is definality been overwritten, and there is no way to recover it in the given time frame. Therefore we need to decrypt the encrypted version, using the correct password gotten from the web resource.

Finally the `sslkeylogfile` contains what seems to be valid SSL session keys. Most likley needed to use to decrypt SSL traffic in the future:

![SSL session key](images/sslkeylogfile.png)

The two files we need for further analysis are `secret.encrypted` and `sslkeylogfile`, we extract them from the disk and keep them in mind.

Since there is nothing we can do unless we get the password we move on to the next file to analysis.
