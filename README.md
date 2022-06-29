# MalWorkz
A Reinforcement Learning Engine for Bypassing Machine Learning Classifiers

>“Mistakes” is the word you’re too embarrassed to use. You ought not to be. You’re a product of a trillion of them. Evolution forged the entirety of sentient life on this planet using only one tool: the mistake.\
>\- *Robert Ford* 

## Overview
MalWorkz is a reinforcment learning engine that attempts to bypass machine learning classifers by manipulating a Portable Executable (PE) file through a set of 6 distinct methods.  Works with x32 PE/.NET/.dll files and with a variety of file formats such as UPX or MSI.  The 6 different obfuscation techniques utilized in this engine are 
1.  Header Randomization
2.  Code Cave Creation
3.  AddressOfEntryPoint Section Encryption
4.  Section Addition
5.  Section Renaming
6.  PE Signing

### Header Randomizatiom
There are a number of PE header's that can be randomly chosen which will not effect the behavior of the PE nor corrupt the image.  The headers which will be manipulated are 
1. `DllCharacteristics`
2. `Characteristics` (File Header)
3. `Debug Directory RVA` (Zeroed Out)
4. `Debug Directory Size` (Zeroed Out)
5. `MajorImageVersion`
6. `MinorImageVersion`
7. `MajorOperatingSystemVersion`
8. `MinorOperatingSystemVersion`
9. `SizeOfStackReserve`
10. `SizeOfStackCommit`
11. `MajorLinkerVersion`
12. `MinorLinkerVersion`
13. `TimeDateStamp`

## Setup
Python version `3.6` <b>MUST</b> be used.  

Install the `requirements.txt` file in a python virtual environment.
```bash
pip install -r requirements.txt
```
Unzip `models.zip`

Install Windows [SignTool](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool).  This tool is used for signing PE files.  The MalWorkz engine will use `SignTool` in conjuction with a supplied `.pfx` file.  After `SignTool` is installed add the location to Windows system environment varibles so that the program may call it.  
