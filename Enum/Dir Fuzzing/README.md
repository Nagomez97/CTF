There are lots of tools to perform web directory and files enumeration.

## gobuster
gobuster dir -u url -w wordlist

## wfuzz
wfuzz -w wordlist --hc 404 http://url

## Tips
When thinking about the wordlist to use, it could be useful to create our own wordlist based on the webpage content. There is a tool called CeWL capable of doing it.
cewl http://url > words.txt
