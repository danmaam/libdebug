import unittest
from libdebug import Debugger
from subprocess import TimeoutExpired
from pwn import process
import time
class Debugger_read(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.d.run("./read_test", sleep=0.1)
        self.mem_addr = 0x1aabbcc1000

    def tearDown(self):
        self.d.stop()

    def test_read_register(self):
        self.assertEqual(self.d.rax, 0x0011223344556677)
        self.assertEqual(self.d.rbx, 0x1122334455667788)
        self.assertEqual(self.d.rcx, 0x2233445566778899)
        self.assertEqual(self.d.rdx, 0x33445566778899aa)
        self.assertEqual(self.d.rdi, 0x445566778899aabb)
        self.assertEqual(self.d.rsi, 0x5566778899aabbcc)
        self.assertEqual(self.d.rsp, 0x66778899aabbccdd)
        self.assertEqual(self.d.rbp, 0x778899aabbccddee)
        self.assertEqual(self.d.r8 , 0x8899aabbccddeeff)
        self.assertEqual(self.d.r9 , 0xffeeddccbbaa9988)
        self.assertEqual(self.d.r10, 0xeeddccbbaa998877)
        self.assertEqual(self.d.r11, 0xddccbbaa99887766)
        self.assertEqual(self.d.r12, 0xccbbaa9988776655)
        self.assertEqual(self.d.r13, 0xbbaa998877665544)
        self.assertEqual(self.d.r14, 0xaa99887766554433)
        self.assertEqual(self.d.r15, 0x9988776655443322)

    def test_read_memory(self):
        self.assertEqual(self.d.mem[self.mem_addr: self.mem_addr+10], b"\xff\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7\xf6")

    def test_brekpoint_relative(self):
        b = self.d.breakpoint(0x10e2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases['main'] + 0x10e2
        self.assertEqual (rip, value)

    def test_step(self):
        b = self.d.breakpoint(0x10e2)
        self.d.cont()
        rip = self.d.rip
        value = self.d.bases['main'] + 0x10ec
        self.d.step()
        rip = self.d.rip
        self.assertEqual (rip, value)


    def test_write_register(self):

        self.d.rax = 0x1234567890abcdef
        self.d.rbx = 0x1234567890abcdef
        self.d.rcx = 0x1234567890abcdef
        self.d.rdx = 0x1234567890abcdef
        self.d.rdi = 0x1234567890abcdef
        self.d.rsi = 0x1234567890abcdef
        self.d.rsp = 0x1234567890abcdef
        self.d.rbp = 0x1234567890abcdef
        self.d.r8  = 0x1234567890abcdef
        self.d.r9  = 0x1234567890abcdef
        self.d.r10 = 0x1234567890abcdef
        self.d.r11 = 0x1234567890abcdef
        self.d.r12 = 0x1234567890abcdef
        self.d.r13 = 0x1234567890abcdef
        self.d.r14 = 0x1234567890abcdef
        self.d.r15 = 0x1234567890abcdef


        self.assertEqual(self.d.rax, 0x1234567890abcdef)
        self.assertEqual(self.d.rbx, 0x1234567890abcdef)
        self.assertEqual(self.d.rcx, 0x1234567890abcdef)
        self.assertEqual(self.d.rdx, 0x1234567890abcdef)
        self.assertEqual(self.d.rdi, 0x1234567890abcdef)
        self.assertEqual(self.d.rsi, 0x1234567890abcdef)
        self.assertEqual(self.d.rsp, 0x1234567890abcdef)
        self.assertEqual(self.d.rbp, 0x1234567890abcdef)
        self.assertEqual(self.d.r8 , 0x1234567890abcdef)
        self.assertEqual(self.d.r9 , 0x1234567890abcdef)
        self.assertEqual(self.d.r10, 0x1234567890abcdef)
        self.assertEqual(self.d.r11, 0x1234567890abcdef)
        self.assertEqual(self.d.r12, 0x1234567890abcdef)
        self.assertEqual(self.d.r13, 0x1234567890abcdef)
        self.assertEqual(self.d.r14, 0x1234567890abcdef)
        self.assertEqual(self.d.r15, 0x1234567890abcdef)


# This is bugged I do not understand yet.
class Debugger_write(unittest.TestCase):
    def setUp(self):
        self.d = Debugger()
        self.p = process("./write_test")
        self.d.attach(self.p.pid)

    def tearDown(self):
        self.d.stop()

    def test_write_memory(self):
        b = self.d.breakpoint(0x1073)

        strings_addr = self.d.bases['main']  + 0x2004
        test_string = b"AAAABBBB"
        self.d.mem[strings_addr:strings_addr+len(test_string)] = test_string

        #print 8 strings
        for i in range(8):
            self.d.cont()

        data = self.p.recv(3000)


        self.assertTrue(test_string in data) 

if __name__ == '__main__':
    unittest.main()