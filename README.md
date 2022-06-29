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

### Code Cave Creation
Code cave creation within a Windows Portable Executable (PE) is an interesting technique to bypass malware classifiers which utilize the entire byte sequence or raw bytes of a PE as their input feature.  Code caves are the "slack space" or byte space within a PE section that is unused by the program, but is created in order to adhere to the `SectionAlignment` header within the PE.  All PE sections must adhere to the byte alignment specified by this header value and if the section data does not directly align itself on this boundary the compiler will add null bytes as padding to ensure that the section is the specified size.

<br/>

Code caves can be created by modifying the `RawAddress` variable within the each section's header.  Arbitrary data can then be added in between each section which can then be used to "confuse" malware classifiers which attempt to use an entire binary's raw data as an input feature.  MalWorkz will create code caves in 512 byte increments and inject randomly chosen data from benign PE sections harvested from Windows SysWOW64 executables.  

<br/>
<p align="center">
  <img width="460" height="300" src="images/code_cave.png">
  <p align="center"><i>Representation of the memory mapping of the original sample and a modified version with unused spaces introduced by the attacker (Yuste et al., 2022)</i></p>
</p>

## Setup
Python version `3.6` <b>MUST</b> be used.  

Install the `requirements.txt` file in a python virtual environment.
```bash
pip install -r requirements.txt
```
Unzip `models.zip`

Install Windows [SignTool](https://docs.microsoft.com/en-us/windows/win32/seccrypto/signtool).  This tool is used for signing PE files.  The MalWorkz engine will use `SignTool` in conjuction with a supplied `.pfx` file.  After `SignTool` is installed add the location to Windows system environment varibles so that the program may call it.  
