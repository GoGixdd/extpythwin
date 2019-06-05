import platform
from ctypes import *
#
# ekknod@2019
#
 
nt = windll.ntdll
k32 = windll.kernel32
u32 = windll.user32
 
 
def array_to_data(address):
    r = 0
    for j in bytearray(reversed(address)):
        r = (r << 8) + j
    return r
 
 
class ProcessList:
    def __init__(self):
        length = c_uint()
        self.snap = create_string_buffer(8)
        nt.NtQuerySystemInformation(57, self.snap, 0x188, pointer(length))
        self.snap = create_string_buffer(length.value + 8192)
        if nt.NtQuerySystemInformation(57, self.snap, length.value + 8192, 0) != 0:
            raise Exception("[!]ProcessList::__init__")
        self.pos = 0
 
    def next(self):
        temp = array_to_data(self.snap[self.pos:self.pos+4])
        if temp != 0:
            self.pos = temp + self.pos
            return True
        return False
 
    def pid(self):
        return int(array_to_data(self.snap[self.pos+0x128:self.pos+0x130]))
 
    def wow64(self):
        return array_to_data(self.snap[self.pos+0x160:self.pos+0x168]) <= 0xffffffff
 
    def teb(self):
        return c_int64(array_to_data(self.snap[self.pos+0x168:self.pos+0x170])).value
 
    def name(self):
        name = create_unicode_buffer(120)
        nt.memcpy(name, c_int64(array_to_data(self.snap[self.pos+0x40:self.pos+0x48])), 120)
        return name.value
 
 
class Process:
    def __init__(self, name):
        temp = c_uint8()
        nt.RtlAdjustPrivilege(20, 1, 0, pointer(temp))
        temp = ProcessList()
        status = False
        while temp.next():
            temp_handle = k32.OpenProcess(0x1fffff, 0, temp.pid())
            if temp.name() == name:
                self.mem = temp_handle
                self.wow64 = temp.wow64()
                if self.wow64:
                    self.peb = self.read_i64(temp.teb() + 0x2030, 4)
                else:
                    self.peb = self.read_i64(temp.teb() + 0x0060, 8)
                status = True
                break
        if not status:
            raise Exception("[!]Process is not running!")
 
    def is_running(self):
        buffer = c_uint32()
        k32.GetExitCodeProcess(self.mem, pointer(buffer))
        return buffer.value == 0x103
 
    def read_string(self, address, length):
        buffer = create_string_buffer(length)
        nt.NtReadVirtualMemory(self.mem, address, buffer, length, 0)
        return buffer.value
 
    def read_unicode(self, address, length):
        buffer = create_unicode_buffer(length)
        nt.NtReadVirtualMemory(self.mem, address, pointer(buffer), length, 0)
        return buffer.value
 
    def read_i16(self, address, length=2):
        buffer = c_uint16()
        nt.NtReadVirtualMemory(self.mem, address, pointer(buffer), length, 0)
        return buffer.value
 
    def read_i32(self, address, length=4):
        buffer = c_uint32()
        nt.NtReadVirtualMemory(self.mem, address, pointer(buffer), length, 0)
        return buffer.value
 
    def read_i64(self, address, length=8):
        buffer = c_uint64()
        nt.NtReadVirtualMemory(self.mem, c_uint64(address), pointer(buffer), length, 0)
        return buffer.value
 
    def write_i16(self, address, value):
        buffer = c_uint16(value)
        return nt.NtWriteVirtualMemory(self.mem, address, pointer(buffer), 2, 0) == 0
 
    def write_i64(self, address, value):
        buffer = c_uint64(value)
        return nt.NtWriteVirtualMemory(self.mem, address, pointer(buffer), 8, 0) == 0
 
    def get_module(self, name):
        if self.wow64:
            a0 = [0x04, 0x0C, 0x14, 0x28, 0x10]
        else:
            a0 = [0x08, 0x18, 0x20, 0x50, 0x20]
        a1 = self.read_i64(self.read_i64(self.peb + a0[1], a0[0]) + a0[2], a0[0])
        a2 = self.read_i64(a1 + a0[0], a0[0])
        while a1 != a2:
            val = self.read_unicode(self.read_i64(a1 + a0[3], a0[0]), 120)
            if str(val).lower() == name.lower():
                return self.read_i64(a1 + a0[4], a0[0])
            a1 = self.read_i64(a1, a0[0])
        raise Exception("[!]Process::get_module")
 
    def get_export(self, module, name):
        if module == 0:
            return 0
        a0 = self.read_i32(module + self.read_i16(module + 0x3C) + (0x88 - self.wow64 * 0x10)) + module
        a1 = [self.read_i32(a0 + 0x18), self.read_i32(a0 + 0x1c), self.read_i32(a0 + 0x20), self.read_i32(a0 + 0x24)]
        while a1[0] > 0:
            a1[0] -= 1
            export_name = self.read_string(module + self.read_i32(module + a1[2] + (a1[0] * 4)), 120)
            if name.encode('ascii', 'ignore') == export_name:
                a2 = self.read_i16(module + a1[3] + (a1[0] * 2))
                a3 = self.read_i32(module + a1[1] + (a2 * 4))
                return module + a3
        raise Exception("[!]Process::get_export")
 
 
class VirtualTable:
    def __init__(self, table):
        self.table = table
 
    def function(self, index):
        return mem.read_i32(mem.read_i32(self.table) + index * 4)
 
 
class InterfaceTable:
    def __init__(self, name):
        self.table_list = mem.read_i32(mem.read_i32(mem.get_export(mem.get_module(name), 'CreateInterface') - 0x6A))
 
    def get_interface(self, name):
        a0 = self.table_list
        while a0 != 0:
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i32(a0 + 0x4), 120)[0:-3]:
                return VirtualTable(mem.read_i32(mem.read_i32(a0) + 1))
            a0 = mem.read_i32(a0 + 0x8)
        raise Exception('[!]InterfaceTable::get_interface')
 
 
class InterfaceList:
    def __init__(self):
        table = InterfaceTable('client_panorama.dll')
        self.client = table.get_interface('VClient')
        self.entity = table.get_interface('VClientEntityList')
 
        table = InterfaceTable('engine.dll')
        self.engine = table.get_interface('VEngineClient')
 
        table = InterfaceTable('inputsystem.dll')
        self.input = table.get_interface('InputSystemVersion')
 
 
class NetVarTable:
    def __init__(self, name):
        self.table = 0
        a0 = mem.read_i32(mem.read_i32(vt.client.function(8) + 1))
        while a0 != 0:
            a1 = mem.read_i32(a0 + 0x0C)
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i32(a1 + 0x0C), 120):
                self.table = a1
            a0 = mem.read_i32(a0 + 0x10)
        if self.table == 0:
            raise Exception('[!]NetVarTable::__init__')
 
    def get_offset(self, name):
        offset = self.__get_offset(self.table, name)
        if offset == 0:
            raise Exception('[!]NetVarTable::get_offset')
        return offset
 
    def __get_offset(self, address, name):
        a0 = 0
        for a1 in range(0, mem.read_i32(address + 0x4)):
            a2 = a1 * 60 + mem.read_i32(address)
            a3 = mem.read_i32(a2 + 0x2C)
            a4 = mem.read_i32(a2 + 0x28)
            if a4 != 0 and mem.read_i32(a4 + 0x4) != 0:
                a5 = self.__get_offset(a4, name)
                if a5 != 0:
                    a0 += a3 + a5
            if name.encode('ascii', 'ignore') == mem.read_string(mem.read_i32(a2), 120):
                return a3 + a0
        return a0
 
 
class NetVarList:
    def __init__(self):
        table = NetVarTable('DT_BasePlayer')
        self.m_iHealth = table.get_offset('m_iHealth')
        self.m_lifeState = table.get_offset('m_lifeState')
        self.m_nTickBase = table.get_offset('m_nTickBase')
 
        table = NetVarTable('DT_BaseEntity')
        self.m_iTeamNum = table.get_offset('m_iTeamNum')
 
        table = NetVarTable('DT_CSPlayer')
        self.m_iCrossHairID = table.get_offset('m_bHasDefuser') + 0x5C
        self.m_iGlowIndex = table.get_offset('m_flFlashDuration') + 0x18
 
        self.entityList = vt.entity.table - (mem.read_i32(vt.entity.function(5) + 0x22) - 0x38)
        self.clientState = mem.read_i32(mem.read_i32(vt.engine.function(18) + 0x16))
        self.getLocalPlayer = mem.read_i32(vt.engine.function(12) + 0x16)
        self.getState = mem.read_i32(vt.engine.function(26) + 0x07)
        self.button = mem.read_i32(vt.input.function(15) + 0x21D)
 
 
class Player:
    def __init__(self, index):
        self.address = mem.read_i32(nv.entityList + index * 0x10)
 
    def is_valid(self):
        if self.address == 0:
            return False
        if self.get_life_state() != 0:
            return False
        health = self.get_health()
        return 0 < health < 1338
 
    def get_health(self):
        return mem.read_i32(self.address + nv.m_iHealth)
 
    def get_team_num(self):
        return mem.read_i32(self.address + nv.m_iTeamNum)
 
    def get_glow_index(self):
        return mem.read_i32(self.address + nv.m_iGlowIndex)
 
    def get_cross_id(self):
        return mem.read_i32(self.address + nv.m_iCrossHairID)
 
    def get_life_state(self):
        return mem.read_i32(self.address + nv.m_lifeState)
 
    def get_tick_count(self):
        return mem.read_i32(self.address + nv.m_nTickBase)
 
 
def is_button_down(button_code):
    return (mem.read_i32(vt.input.table + (((button_code >> 5) * 4) + nv.button)) >> (button_code & 31)) & 1
 
 
def should_shoot(c_id, t_num):
    target = Player(c_id - 1)
    return target.is_valid() and target.get_team_num() != t_num and target.get_health() > 0
 
 
if __name__ == "__main__":
    global mem
    global vt
    global nv
    if platform.architecture()[0] != '64bit':
        print('[!]64bit python required')
        exit(0)
    try:
        mem = Process('csgo.exe')
        vt = InterfaceList()
        nv = NetVarList()
    except Exception as e:
        print(e)
        exit(0)
    previous_tick = 0
    while mem.is_running():
        if mem.read_i32(nv.clientState + nv.getState) == 6:
            self = Player(mem.read_i32(nv.clientState + nv.getLocalPlayer))
            team_num = self.get_team_num()
            if is_button_down(111) and should_shoot(self.get_cross_id(), team_num):
                current_tick = self.get_tick_count()
                if current_tick - previous_tick > 2:
                    u32.mouse_event(0x0002, 0, 0, 0, 0)
                    u32.mouse_event(0x0004, 0, 0, 0, 0)
                    previous_tick = current_tick
