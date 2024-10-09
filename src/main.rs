#![allow(static_mut_refs)]
/*!#![feature(sync_unsafe_cell)]
use std::cell::SyncUnsafeCell;
use std::sync::Mutex;*/
use std::time::SystemTime;
use std::thread;
use std::fs;
use std::env;
use macroquad::prelude::*;

mod exit;


fn get_sys_time() -> u64 {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(n) => n.as_nanos() as u64,
        Err(_) => panic!("SystemTime before UNIX EPOCH!"),
    }
}


static mut RAM: Vec<u8> = Vec::new();

static mut PORT: [u16; 64 << 10] = [0; 64 << 10];

const PAGE_SIZE: usize = 100 << 10;

/*
Ram size: 4000 0000

Page size: 1 9000

Number of pages: 28F5

Last page: 3FFE D000 - 4000 0000 = 1 3000
*/

static mut DRIVE: Vec<u8> = Vec::new();

static mut DRIVE_FLAGS: Vec<usize> = Vec::new();

static mut GAME_TIME: u64 = 0;

unsafe fn init() {
    GAME_TIME = get_sys_time();
    RAM = vec![0; 1 << 30];
    DRIVE = vec![0; 2 << 30];

    let mut path = env::current_exe().unwrap();
    path.pop();
    path.push("saves");
    path.push("drive");

    fs::create_dir_all(&path).unwrap();

    for f in fs::read_dir(path).unwrap() {
        let index = usize::from_str_radix(&f.as_ref().unwrap().file_name().into_string().unwrap(), 16).unwrap();

        let bytes = fs::read(f.unwrap().path()).unwrap();

        //println!("{:?}", bytes);

        DRIVE[index*PAGE_SIZE..index*PAGE_SIZE + bytes.len()].copy_from_slice(&bytes[0..bytes.len()]);
    }
}


fn get_ram(address: usize, bytes: usize) -> u64 { unsafe {
    let mut b = [0; 8];
    b[8-bytes..].copy_from_slice(&RAM[address..address + bytes]);
    u64::from_be_bytes(b)
}}

fn put_ram(address: usize, bytes: usize, number: u64) {unsafe {
    RAM[address..address + bytes].copy_from_slice(&number.to_be_bytes()[8-bytes..])
}}

fn sgram(process: &mut Option<Process>, address: usize, bytes: usize) -> u64 {
    if let Some(process) = process {
        let mut access = false;

        for page_id in process.pages_read {
            if address + bytes - 1 >= page_id as usize * PAGE_SIZE && 
                address + bytes - 1 < (page_id as usize + 1) * PAGE_SIZE {

                access = true;
                break;
            }
        }

        if access || process.elite {
            return get_ram(address, bytes);
        }

        process.exit(exit::MEMORY_READ_VIOLATION);
    }
    
    return 0;   
}

fn spram(process: &mut Option<Process>, address: usize, bytes: usize, number: u64) {
    if let Some(process) = process {
        let mut access = false;

        for page_id in process.pages_write {
            if address + bytes - 1 >= page_id as usize * PAGE_SIZE && 
                address + bytes - 1 < (page_id as usize + 1) * PAGE_SIZE {

                access = true;
                break;
            }
        }

        if access || process.elite {
            put_ram(address, bytes, number);
            return;
        }
        
        process.exit(exit::MEMORY_WRITE_VIOLATION);
    }
}

fn rgram(process: &mut Option<Process>, address: usize, bytes: usize) -> u64 {
    if let Some(process) = process {
        let page = address / PAGE_SIZE;
        let r_addr = address - PAGE_SIZE * page;

        let mut pages: Vec<usize> = process.pages_write.iter().map(|x| x.to_owned() as usize).collect();
        pages.retain(|&x| x != 0xFFFF);

        if page >= pages.len() {
            process.exit(exit::MEMORY_OUT_OF_BOUNDS);

            return 0;
        }

        let a_addr = PAGE_SIZE * pages[page] + r_addr;
        
        return get_ram(a_addr, bytes);
    }
    return 0;
}

fn rpram(process: &mut Option<Process>, address: usize, bytes: usize, number: u64) {
    if let Some(process) = process {
        let page = address / PAGE_SIZE;
        let r_addr = address - PAGE_SIZE * page;

        let mut pages: Vec<usize> = process.pages_write.iter().map(|x| x.to_owned() as usize).collect();
        pages.retain(|&x| x != 0xFFFF);

        if page >= pages.len() {
            process.exit(exit::MEMORY_OUT_OF_BOUNDS);

            return;
        }

        let a_addr = PAGE_SIZE * pages[page] + r_addr;

        put_ram(a_addr, bytes, number);
    }
}

fn rrogram(process: &mut Option<Process>, address: usize, bytes: usize) -> u64 {
    if process.as_ref().unwrap().absolute { return sgram( process, address, bytes) } 

    if let Some(process) = process {

        let page = address / PAGE_SIZE;
        let r_addr = address - PAGE_SIZE * page;

        let mut pages: Vec<usize> = process.pages_read.iter().map(|x| x.to_owned() as usize).collect();
        pages.retain(|&x| x != 0xFFFF);

        if page >= pages.len() {
            process.exit(exit::MEMORY_OUT_OF_BOUNDS);

            return 0;
        }

        let a_addr = PAGE_SIZE * pages[page] + r_addr;
        
        return get_ram(a_addr, bytes);
    }
    return 0;
}


fn get_drive(address: usize, bytes: usize) -> u64 { unsafe {
    let mut b = [0; 8];
    b[8-bytes..].copy_from_slice(&DRIVE[address..address + bytes]);
    u64::from_be_bytes(b)
}}

fn put_drive(address: usize, bytes: usize, number: u64) { unsafe {
    DRIVE[address..address + bytes].copy_from_slice(&number.to_be_bytes()[8-bytes..]);

    let page = address / PAGE_SIZE;
    if !DRIVE_FLAGS.contains(&page) { DRIVE_FLAGS.push(page) }
}}

fn sgdrive(process: &mut Option<Process>, address: usize, bytes: usize) -> u64 {
    if let Some(process) = process {
        if process.elite { return get_drive(address, bytes) }
        else { process.exit(exit::DRIVE_ACCESS_VIOLATION) }
    }
    return 0;
}

fn spdrive(process: &mut Option<Process>, address: usize, bytes: usize, number: u64) {
    if let Some(process) = process {
        if process.elite { put_drive(address, bytes, number) }
        else { process.exit(exit::DRIVE_ACCESS_VIOLATION) }
    }
}

#[macroquad::main("VM")]
async fn main() {unsafe {
    init();
    
    { // Init Kernel
        let mut proc = Process::new(0, 0, String::from("Kernel"), PAGE_SIZE*3);

        proc.pages_read[0] = 0x0;
        proc.pages_write[0] = 0x0;

        let bytes = proc.to_bytes();

        for i in 0..PROCESS_LEN {
            put_ram(PAGE_SIZE + i, 1, bytes[i] as u64);
        }

        for i in 0..1024 + 0x1_0000 {
            put_ram(PAGE_SIZE*3 + i, 1, get_drive(i, 1));
        }
    }

    for _ in 0..1 {
        thread::spawn(move || {Core64::new().run()});
    }

    let screen_size = Vec2::new(800., 600.);
    loop {
        draw_screen(screen_size);

        next_frame().await;
    }
}}

unsafe fn draw_screen(screen_size: Vec2) {
    let bytes: Vec<u8> = RAM[(0x4000_0000 - (screen_size.x * screen_size.y) as usize * 3)..0x4000_0000].iter().map(|x| x.to_owned()).collect();
    let mut buffer = Vec::new();

    let mut i = 0;
    while i < bytes.len(){
        buffer.push(bytes[i]);
        buffer.push(bytes[i+1]);
        buffer.push(bytes[i+2]);
        buffer.push(0xFF);

        i += 3;
    }

    let texture = Texture2D::from_rgba8(screen_size.x as u16, screen_size.y as u16, &buffer);
    texture.set_filter(FilterMode::Nearest);

    let mut scale = screen_width() / screen_size.x;
    if screen_height() < screen_size.y * scale {scale = screen_height() / screen_size.y}

    let frame = Vec2::new(screen_width()/2. - screen_size.x/2. * scale, screen_height()/2. - screen_size.y/2. * scale);

    draw_texture_ex(
        &texture, 
        frame.x,
        frame.y,
        WHITE,
        DrawTextureParams {
            dest_size: Some(Vec2::new(screen_size.x * scale, screen_size.y * scale)),
            ..Default::default()
        }
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessState {
    Terminate = 0,
    Running = 1,
    Paused = 2,
    Swapped = 3,
    Ready = 4,
}

const PROCESS_LEN: usize = 573;

#[derive(Debug, Clone)]
struct Process {
    pid: usize,
    ppid: usize,
    name: String,

    elite: bool,
    absolute: bool,

    pc: usize,
    sp: usize,

    cf: bool,

    state: ProcessState,
    
    pages_read: [u16; 128],
    pages_write: [u16; 128],

    resume_time: u64,

    exit_code: u16,
}

impl Process {
    fn exit(&mut self, exit_code: u16) {
        self.state = ProcessState::Terminate;
        self.exit_code = exit_code;
    }

    fn new(pid: usize, ppid: usize, name: String, pc: usize) -> Self {
        Process {
            pid,
            ppid,
            name,
            elite: true,
            absolute: true,
            pc,
            sp: 0xC800,
            cf: false,
            state: ProcessState::Ready,
            pages_read: [0xFFFF; 128],
            pages_write: [0xFFFF; 128],
            resume_time: 0,
            exit_code: 0,
        }
    }

    fn to_bytes(self) -> [u8; PROCESS_LEN] {
        let mut bytes: [u8; PROCESS_LEN] = [0; PROCESS_LEN];
           
        bytes[0..8].copy_from_slice(&self.pid.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.ppid.to_be_bytes());

        let name_bytes = self.name.as_bytes();
        bytes[16..16+name_bytes.len()].copy_from_slice(name_bytes);

        bytes[32] = (self.elite as u8) << 4 | self.absolute as u8;

        bytes[33..41].copy_from_slice(&self.pc.to_be_bytes());
        bytes[41..49].copy_from_slice(&self.sp.to_be_bytes());

        bytes[49] = self.cf as u8;

        bytes[50] = self.state as u8;

        bytes[51..307].copy_from_slice(&self.pages_read.map(|x| x.to_be_bytes()).concat());
        bytes[307..563].copy_from_slice(&self.pages_write.map(|x| x.to_be_bytes()).concat());

        bytes[563..571].copy_from_slice(&self.resume_time.to_be_bytes());

        bytes[571..PROCESS_LEN].copy_from_slice(&self.exit_code.to_be_bytes());

        bytes
    }

    fn from_bytes(bytes: [u8; PROCESS_LEN]) -> Self {
        let mut pages_read = [0; 128];
        let mut pages_write = [0; 128];

        pages_read.copy_from_slice(bytes[49..305].chunks(2).map(|x| u16::from_be_bytes(x.try_into().unwrap())).collect::<Vec<u16>>().as_slice());
        pages_write.copy_from_slice(bytes[305..561].chunks(2).map(|x| u16::from_be_bytes(x.try_into().unwrap())).collect::<Vec<u16>>().as_slice());

        Process {
            pid: usize::from_be_bytes(bytes[0..8].try_into().unwrap()),
            ppid: usize::from_be_bytes(bytes[8..16].try_into().unwrap()),
            name: String::from_utf8(bytes[16..32].to_vec()).unwrap_or(u128::from_be_bytes(bytes[16..32].try_into().unwrap()).to_string()),
            elite: bytes[32] & 0x10 == 0x10,
            absolute: bytes[32] & 0x1 == 0x1,
            pc: usize::from_be_bytes(bytes[33..41].try_into().unwrap()),
            sp: usize::from_be_bytes(bytes[41..49].try_into().unwrap()),
            cf: bytes[49] == 1,
            state: unsafe { core::mem::transmute(bytes[50]) },
            pages_read,
            pages_write,
            resume_time: u64::from_be_bytes(bytes[563..571].try_into().unwrap()),
            exit_code: u16::from_be_bytes(bytes[571..PROCESS_LEN].try_into().unwrap()),
        }
    }
}

struct Core64 {
    process: Option<Process>,

    regs: [u64; 16],
    fregs: [f64; 16],
    cf: bool,

    pc: usize,
    sp: usize,
}

impl Core64 {
    fn new() -> Self {
        Core64 {
            process: None,
            regs: [0; 16],
            fregs: [0.; 16],
            cf: false,
            pc: 0x0,
            sp: 0xC800,
        }
    }

    fn get_process(&mut self) -> usize {
        let mut first = true;
        loop {
            for i in 0..357 {
                let addr = PAGE_SIZE + i * PROCESS_LEN;
                let state = get_ram(addr + 50, 1);
                put_ram(addr + 50, 1, ProcessState::Running as u64);

                if ((state == ProcessState::Ready as u64 || state == ProcessState::Paused as u64 || state == ProcessState::Swapped as u64) && get_ram(addr + 563, 8) < get_sys_time()) || 
                    (!first && state == ProcessState::Swapped as u64) {unsafe{

                    let bytes: Vec<u8> = RAM[addr..addr + PROCESS_LEN].iter().map(|x| x.to_owned()).collect();
                    
                    let mut proc = Process::from_bytes(bytes.try_into().unwrap());

                    if proc.state == ProcessState::Paused || proc.state == ProcessState::Swapped {
                        for i in 0..16 {
                            proc.sp -= 16;
                            self.regs[15-i] = rgram(&mut self.process, proc.sp, 8);
                            self.fregs[15-i] = f64::from_be_bytes(rgram(&mut self.process, proc.sp+8, 8).to_be_bytes());   
                        }
                        self.sp = proc.sp;
                    }
                    self.pc = proc.pc;

                    self.process = Some(proc);
                    return addr;
                }}
                else {
                    put_ram(addr + 50, 1, state);
                }
            }
            first = false;
        }
    }

    fn swap_process(&mut self, proc_index: usize) -> usize {
        if let Some(proc) = &mut self.process.clone() {

            let clone_proc = &mut self.process.clone();

            proc.sp = self.sp;
            proc.pc = self.pc;

            for i in 0..16 {
                rpram(clone_proc, proc.sp, 8, self.regs[i]);
                rpram(clone_proc, proc.sp+8, 8, u64::from_be_bytes(self.fregs[i].to_be_bytes()));
                proc.sp += 16;
            }

            let state = ProcessState::Swapped;
            
            proc.resume_time = get_sys_time() + 1000;
            unsafe{RAM[proc_index..proc_index + PROCESS_LEN].copy_from_slice(&proc.clone().to_bytes())}

            put_ram(proc_index + 50, 1, state as u64);
        }
        self.get_process()
    }

    fn pause_process(&mut self, proc_index: usize) -> usize {
        if let Some(proc) = &mut self.process.clone() {

            let clone_proc = &mut self.process.clone();

            proc.sp = self.sp;
            proc.pc = self.pc;

            for i in 0..16 {
                rpram(clone_proc, proc.sp, 8, self.regs[i]);
                rpram(clone_proc, proc.sp+8, 8, u64::from_be_bytes(self.fregs[i].to_be_bytes()));
                proc.sp += 16;
            }

            proc.state = ProcessState::Paused;
            
            unsafe{RAM[proc_index..proc_index + PROCESS_LEN].copy_from_slice(&proc.clone().to_bytes())}
        }
        self.get_process()
    }

    fn terminate_process(&mut self, proc_index: usize) -> usize {
        if let Some(proc) = &mut self.process.clone() {
            proc.sp = self.sp;
            proc.pc = self.pc;

            println!("Process {} with pid {} and ppid {} was terminated with exit code {:04x}", proc.name, proc.pid, proc.ppid, proc.exit_code);
            
            unsafe{RAM[proc_index..proc_index + PROCESS_LEN].copy_from_slice(&proc.clone().to_bytes())}
        }
        self.get_process()
    }

    fn run(&mut self) {
        let mut proc_index = 0;
        let mut inst_count = 0;
        loop {
            if self.process.is_none() {
                proc_index = self.get_process();
            }
            if inst_count > 0x1000 {
                inst_count = 0;
                proc_index = self.swap_process(proc_index);
            }
            inst_count += 1;

            //let page = self.pc / PAGE_SIZE; let r_addr = self.pc - PAGE_SIZE * page; let a_addr = PAGE_SIZE * 3 + r_addr; println!("{:0x} | {:2x} | {:0x}: {{{:2x}}} {:08x?}", page, r_addr, a_addr, rrogram(&mut self.process, self.pc, 1), self.regs);

            match rrogram(&mut self.process, self.pc, 1) {
                /* NOP () */ 0x00 => {}

                /* MOV U2U (1b reg id, 1b reg id) */ 0x01 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize];
                    self.pc += 2;
                }
                /* MOV F2F (1b reg id, 1b reg id) */ 0x02 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize];
                    self.pc += 2;
                }
                /* MOV U2F (1b reg id, 1b reg id) */ 0x03 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as f64;
                    self.pc += 2;
                }
                /* MOV F2U (1b reg id, 1b reg id) */ 0x04 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as u64;
                    self.pc += 2;
                }
                
                /* MOV I2U (1b reg id, 8b num) */ 0x05 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = rrogram(&mut self.process, self.pc + 2, 8);
                    self.pc += 9;
                }
                /* MOV I2F (1b reg id, 8b num) */ 0x06 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = f64::from_be_bytes(rrogram(&mut self.process, self.pc + 2, 8).to_be_bytes());
                    self.pc += 9;
                }
                
                /* MOV M2U (1b reg id, 1b len, 4b addr) */ 0x07 => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        rgram(&mut self.process, addr, bytes);

                    self.pc += 6;
                }
                /* MOV M2F (1b reg id, 1b len, 4b addr) */ 0x08 => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(rgram(&mut self.process, addr, bytes).to_be_bytes());
                    
                    self.pc += 6;
                }
                /* MOV U2M (4b addr, 1b len, 1b reg id) */ 0x09 => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 6, 1) as usize];

                    rpram(&mut self.process, addr, bytes,num);
                    self.pc += 6;
                }
                /* MOV F2M (4b addr, 1b len, 1b reg id) */ 0x0A => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 6, 1) as usize].to_be_bytes());

                    rpram(&mut self.process,addr, bytes, num);
                    
                    self.pc += 6;
                }

                /* MOV U2MWP (1b reg id, 1b len, 1b reg id) */ 0x0B => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    rpram(&mut self.process,addr,bytes,num);

                    self.pc += 3;
                }
                /* MOV F2MWP (1b reg id, 1b len, 1b reg id) */ 0x0C => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    rpram(&mut self.process, addr, bytes, num);

                    self.pc += 3;
                }
                /* MOV M2UWP (1b reg id, 1b len, 1b reg id) */ 0x0D => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        rgram(&mut self.process, addr, bytes);

                    self.pc += 3;
                }
                /* MOV M2FWP (1b reg id, 1b len, 1b reg id) */ 0x0E => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(rgram(&mut self.process,addr, bytes).to_be_bytes());
                    
                    self.pc += 3;
                }

                /* MOV AM2U (1b reg id, 1b len, 4b addr) */ 0x0F => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgram(&mut self.process, addr, bytes);

                    self.pc += 6;
                }
                /* MOV AM2F (1b reg id, 1b len, 4b addr) */ 0x10 => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgram(&mut self.process, addr, bytes).to_be_bytes());
                    
                    self.pc += 6;
                }
                /* MOV U2AM (4b addr, 1b len, 1b reg id) */ 0x11 => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 6, 1) as usize];

                    spram(&mut self.process, addr, bytes,num);
                    self.pc += 6;
                }
                /* MOV F2AM (4b addr, 1b len, 1b reg id) */ 0x12 => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 6, 1) as usize].to_be_bytes());

                    spram(&mut self.process,addr, bytes, num);
                    
                    self.pc += 6;
                }

                /* MOV U2AMWP (1b reg id, 1b len, 1b reg id) */ 0x13 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    spram(&mut self.process,addr,bytes,num);

                    self.pc += 3;
                }
                /* MOV F2AMWP (1b reg id, 1b len, 1b reg id) */ 0x14 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    spram(&mut self.process, addr, bytes, num);

                    self.pc += 3;
                }
                /* MOV AM2UWP (1b reg id, 1b len, 1b reg id) */ 0x15 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgram(&mut self.process, addr, bytes);

                    self.pc += 3;
                }
                /* MOV AM2FWP (1b reg id, 1b len, 1b reg id) */ 0x16 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgram(&mut self.process,addr, bytes).to_be_bytes());
                    
                    self.pc += 3;
                }

                /* MOV U2MWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x17 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    rpram(&mut self.process,addr,bytes,num);

                    self.pc += 4;
                }
                /* MOV F2MWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x18 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    rpram(&mut self.process,addr,bytes,num);
                    
                    self.pc += 4;
                }
                /* MOV M2UWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x19 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        rgram(&mut self.process, addr, bytes);

                    self.pc += 4;
                }
                /* MOV M2FWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x1A => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(rgram(&mut self.process, addr, bytes).to_be_bytes());
                    
                    self.pc += 4;
                }

                /* MOV U2AMWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x1B => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    spram(&mut self.process,addr,bytes,num);

                    self.pc += 4;
                }
                /* MOV F2AMWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x1C => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    spram(&mut self.process, addr, bytes, num);

                    self.pc += 4;
                }
                /* MOV AM2UWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x1D => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgram(&mut self.process, addr, bytes);

                    self.pc += 4;
                }
                /* MOV AM2FWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x1E => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgram(&mut self.process,addr, bytes).to_be_bytes());
                    
                    self.pc += 4;
                }

                /* MOV D2U (1b reg id, 1b len, 4b addr) */ 0x1F => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgdrive(&mut self.process, addr, bytes);

                    self.pc += 6;
                }
                /* MOV D2F (1b reg id, 1b len, 4b addr) */ 0x20 => {
                    let addr = rrogram(&mut self.process, self.pc + 3, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgdrive(&mut self.process, addr, bytes).to_be_bytes());
                    
                    self.pc += 6;
                }
                /* MOV U2D (4b addr, 1b len, 1b reg id) */ 0x21 => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 6, 1) as usize];

                    spdrive(&mut self.process, addr, bytes,num);
                    self.pc += 6;
                }
                /* MOV F2D (4b addr, 1b len, 1b reg id) */ 0x22 => {
                    let addr = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 5, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 6, 1) as usize].to_be_bytes());

                    spdrive(&mut self.process,addr, bytes, num);
                    
                    self.pc += 6;
                }

                /* MOV U2DWP (1b reg id, 1b len, 1b reg id) */ 0x23 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    spdrive(&mut self.process,addr,bytes,num);

                    self.pc += 3;
                }
                /* MOV F2DWP (1b reg id, 1b len, 1b reg id) */ 0x24 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    spdrive(&mut self.process, addr, bytes, num);

                    self.pc += 3;
                }
                /* MOV D2UWP (1b reg id, 1b len, 1b reg id) */ 0x25 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgdrive(&mut self.process, addr, bytes);

                    self.pc += 3;
                }
                /* MOV D2FWP (1b reg id, 1b len, 1b reg id) */ 0x26 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgdrive(&mut self.process,addr, bytes).to_be_bytes());
                    
                    self.pc += 3;
                }

                /* MOV U2DWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x27 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];

                    spdrive(&mut self.process,addr,bytes,num);

                    self.pc += 4;
                }
                /* MOV F2DWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x28 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize].to_be_bytes());

                    spdrive(&mut self.process, addr, bytes, num);

                    self.pc += 4;
                }
                /* MOV D2UWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x29 => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        sgdrive(&mut self.process, addr, bytes);

                    self.pc += 4;
                }
                /* MOV D2FWP&I (1b reg id, 1b len, 1b reg id, 4b addr) */ 0x2A => {
                    let addr = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize + rrogram(&mut self.process, self.pc + 4, 4) as usize;
                    let bytes = rrogram(&mut self.process, self.pc + 2, 1) as usize;

                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        f64::from_be_bytes(sgdrive(&mut self.process,addr, bytes).to_be_bytes());
                    
                    self.pc += 4;
                }

                /* ADD U2U (1b reg id, 1b reg id, 1b reg id) */ 0x30 => {
                    (self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize], self.cf) = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize].overflowing_add( 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize]);
                    self.pc += 3;
                }
                /* ADD F2F (1b reg id, 1b reg id, 1b reg id) */ 0x31 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] +
                        self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
            
                /* SUB U2U (1b reg id, 1b reg id, 1b reg id) */ 0x32 => {
                    (self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize], self.cf) = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize].overflowing_sub( 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize]);
                    self.pc += 3;
                }
                /* SUB F2F (1b reg id, 1b reg id, 1b reg id) */ 0x33 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] -
                        self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
                
                /* MUL U2U (1b reg id, 1b reg id, 1b reg id) */ 0x34 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        u64::from_be_bytes((self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as i64 * 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as i64).to_be_bytes());
                    self.pc += 3;
                }
                /* MUL F2F (1b reg id, 1b reg id, 1b reg id) */ 0x35 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] *
                        self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }

                /* DIV U2U (1b reg id, 1b reg id, 1b reg id) */ 0x36 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        u64::from_be_bytes((self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as i64 / 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as i64).to_be_bytes());
                    self.pc += 3;
                }
                /* DIV F2F (1b reg id, 1b reg id, 1b reg id) */ 0x37 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] /
                        self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }

                /* MOD U2U (1b reg id, 1b reg id, 1b reg id) */ 0x38 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        u64::from_be_bytes((self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as i64 % 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as i64).to_be_bytes());
                    self.pc += 3;
                }
                /* MOD F2F (1b reg id, 1b reg id, 1b reg id) */ 0x39 => {
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] %
                        self.fregs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }

                /* SHL (1b reg id, 1b reg id, 1b reg id) */ 0x3A => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] << 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
                /* SHR (1b reg id, 1b reg id, 1b reg id) */ 0x3B => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] >> 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }

                /* AND (1b reg id, 1b reg id, 1b reg id) */ 0x3C => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] & 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
                /* OR (1b reg id, 1b reg id, 1b reg id) */ 0x3D => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] | 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
                /* XOR (1b reg id, 1b reg id, 1b reg id) */ 0x3E => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] ^ 
                        self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize];
                    self.pc += 3;
                }
                /* NOT (1b reg id, 1b reg id) */ 0x3F => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = 
                        !self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize];
                    self.pc += 2;
                }

                /* INC (1b reg id) */ 0x40 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] += 1;
                    self.pc += 1;
                }
                /* DEC (1b reg id) */ 0x41 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] -= 1;
                    self.pc += 1;
                }

                /* PSH U (1b reg id) */ 0x42 => {
                    let num = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize];
                    rpram(&mut self.process, self.sp, 8, num);
                    
                    self.pc += 1;
                    self.sp += 8;
                }
                /* PSH F (1b reg id) */ 0x43 => {
                    let num = u64::from_be_bytes(self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize].to_be_bytes());
                    rpram(&mut self.process, self.sp, 8, num);

                    self.pc += 1;
                    self.sp += 8;
                }

                /* POP U (1b reg id) */ 0x44 => {
                    self.sp -= 8;
                    
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = rgram(&mut self.process, self.sp, 8);

                    self.pc += 1;
                }
                /* POP F (1b reg id) */ 0x45 => {
                    self.sp -= 8;
                    
                    self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = f64::from_be_bytes(rgram(&mut self.process, self.sp, 8).to_be_bytes());

                    self.pc += 1;
                }

                /* ADC (1b reg id) */ 0x46 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] += self.cf as u64;
                    self.pc += 1;
                }
                /* SBC (1b reg id) */ 0x47 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] -= self.cf as u64;
                    self.pc += 1;
                }

                /* SCF () */ 0x48 => {
                    self.cf = true;
                }
                /* CCF () */ 0x49 => {
                    self.cf = false;
                }

                /* JMP I (4b addr) */ 0x50 => {
                    self.pc = rrogram(&mut self.process, self.pc + 1, 4) as usize - 1;
                }
                /* JMP R (1b reg id) */ 0x51 => {
                    self.pc = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize - 1;
                }

                /* JLG UI (1b reg id, 1b reg id, 4b addr) */ 0x52 => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] < self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JLG UR (1b reg id, 1b reg id, 1b reg id) */ 0x53 => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] < self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }
                /* JLG FI (1b reg id, 1b reg id, 4b addr) */ 0x54 => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] < self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JLG FR (1b reg id, 1b reg id, 1b reg id) */ 0x55 => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] < self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }

                /* JPE UI (1b reg id, 1b reg id, 4b addr) */ 0x56 => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] == self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JPE UR (1b reg id, 1b reg id, 1b reg id) */ 0x57 => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] == self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }
                /* JPE FI (1b reg id, 1b reg id, 4b addr) */ 0x58 => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] == self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JPE FR (1b reg id, 1b reg id, 1b reg id) */ 0x59 => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] == self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }

                /* JNE UI (1b reg id, 1b reg id, 4b addr) */ 0x5A => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] != self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JNE UR (1b reg id, 1b reg id, 1b reg id) */ 0x5B => {
                    if self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] != self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }
                /* JNE FI (1b reg id, 1b reg id, 4b addr) */ 0x5C => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] != self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = rrogram(&mut self.process, self.pc + 3, 4) as usize - 1;
                    } else {
                        self.pc += 6;
                    }
                }
                /* JNE FR (1b reg id, 1b reg id, 1b reg id) */ 0x5D => {
                    if self.fregs[rrogram(&mut self.process, self.pc + 1, 1) as usize] != self.fregs[rrogram(&mut self.process, self.pc + 2, 1) as usize] {
                        self.pc = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize - 1;
                    } else {
                        self.pc += 3;
                    }
                }

                /* JPC I (4b addr) */ 0x5E => {
                    if self.cf { self.pc = rrogram(&mut self.process, self.pc + 1, 4) as usize - 1 }
                    else { self.pc += 4 }
                }
                /* JPC R (1b reg id) */ 0x5F => {
                    if self.cf { self.pc = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize - 1 }
                    else { self.pc += 1 }
                }

                /* JNC I (4b addr) */ 0x60 => {
                    if !self.cf { self.pc = rrogram(&mut self.process, self.pc + 1, 4) as usize - 1 }
                    else { self.pc += 4 }
                }
                /* JNC R (1b reg id) */ 0x61 => {
                    if !self.cf { self.pc = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize - 1 }
                    else { self.pc += 1 }
                }

                /* HLT () */ 0x70 => {
                    todo!("Halt");
                }

                /* WIT I (8b num) */ 0x71 => {
                    self.process.as_mut().unwrap().resume_time = get_sys_time() + rrogram(&mut self.process, self.pc + 1, 8);
                    self.pc += 8;

                    inst_count = 0;
                    proc_index = self.pause_process(proc_index);
                }
                /* WIT R (1b reg id) */ 0x72 => {
                    self.process.as_mut().unwrap().resume_time = get_sys_time() + self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize];
                    self.pc += 2;

                    inst_count = 0;
                    proc_index = self.pause_process(proc_index);
                }

                /* GST (1b reg id) */ 0x73 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = unsafe { get_sys_time() - GAME_TIME as u64 };
                    self.pc += 1;
                }

                /* GPC (1b reg id) */ 0x74 => {
                    self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = self.pc as u64;
                    self.pc += 1;
                }

                /* SYSCAL () */ 0x80 => {
                    rpram(&mut self.process, self.sp, 4, self.pc as u64);
                    self.process.as_mut().unwrap().elite = true;
                    self.process.as_mut().unwrap().absolute = true;
                    self.pc = 0_usize.wrapping_sub(1);
                }
                /* SYSRET () */ 0x81 => {
                    self.pc = rgram(&mut self.process, self.sp, 4) as usize;
                    self.process.as_mut().unwrap().elite = false;
                    self.process.as_mut().unwrap().absolute = true;
                }
                
                /* MEMCPY II (4b addr, 4b addr, 3b len) */ 0x82 => {
                    if self.process.as_ref().unwrap().elite {
                        let src = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                        let dst = rrogram(&mut self.process, self.pc + 5, 4) as usize;
                        let len = rrogram(&mut self.process, self.pc + 9, 3);

                        unsafe { RAM[dst..dst + len as usize].copy_from_slice(&RAM[src..src + len as usize]) }

                        self.pc += 11;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }
                /* MEMCPY RI (1b reg id, 1b reg id, 3b len) */ 0x83 => {
                    if self.process.as_ref().unwrap().elite {
                        let src = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                        let dst = self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as usize;
                        let len = rrogram(&mut self.process, self.pc + 3, 3);

                        unsafe { RAM[dst..dst + len as usize].copy_from_slice(&RAM[src..src + len as usize]) }

                        self.pc += 5;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }
                /* MEMCPY RR (1b reg id, 1b reg id, 1b reg id) */ 0x84 => {
                    if self.process.as_ref().unwrap().elite {
                        let src = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                        let dst = self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as usize;
                        let len = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;

                        unsafe { RAM[dst..dst + len].copy_from_slice(&RAM[src..src + len]) }

                        self.pc += 4;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }

                /* OUT I (1b reg id, 2b port) */ 0x90 => { 
                    if self.process.as_ref().unwrap().elite {
                        unsafe { PORT[rrogram(&mut self.process, self.pc + 2, 2) as usize] = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as u16 };
                        self.pc += 3;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }
                /* OUT R (1b reg id, 1b reg id) */ 0x91 => {
                    if self.process.as_ref().unwrap().elite {
                        unsafe { PORT[self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as usize] = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as u16 };
                        self.pc += 2;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }

                /* IN I (1b reg id, 2b port) */ 0x92 => {
                    if self.process.as_ref().unwrap().elite {
                        self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = unsafe { PORT[rrogram(&mut self.process, self.pc + 2, 2) as usize] as u64 };
                        self.pc += 3;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }
                /* IN R (1b reg id, 1b reg id) */ 0x93 => {
                    if self.process.as_ref().unwrap().elite {
                        self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] = unsafe { PORT[self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as usize] as u64 };
                        self.pc += 2;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }

                /* GRAPCPY I (4b addr, 1b reg id, 2b h, 2b w) */ 0xA0 => {
                    if self.process.as_ref().unwrap().elite {
                        let src = rrogram(&mut self.process, self.pc + 1, 4) as usize;
                        let dst = self.regs[rrogram(&mut self.process, self.pc + 5, 1) as usize] as usize;
                        let h = rrogram(&mut self.process, self.pc + 6, 2) as usize;
                        let w = rrogram(&mut self.process, self.pc + 8, 2) as usize;
                        let x = rrogram(&mut self.process, self.pc + 10, 2) as usize;
                        let y = rrogram(&mut self.process, self.pc + 12, 2) as usize;

                        for line in 0..h {
                            unsafe { RAM[dst + 0x960*y + 0x960*line + x*3 .. dst + 0x960*y + 0x960*line + x*3 + w*3].copy_from_slice(&RAM[src + w*3*line .. src + w*3*line + w*3]) }
                        }

                        self.pc += 9;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }
                /* GRAPCPY R (1b reg id, 1b reg id, 1b reg id, 1b reg id) */ 0xA1 => {
                    if self.process.as_ref().unwrap().elite {
                        let src = self.regs[rrogram(&mut self.process, self.pc + 1, 1) as usize] as usize;
                        let dst = self.regs[rrogram(&mut self.process, self.pc + 2, 1) as usize] as usize;
                        let h = self.regs[rrogram(&mut self.process, self.pc + 3, 1) as usize] as usize;
                        let w = self.regs[rrogram(&mut self.process, self.pc + 4, 1) as usize] as usize;
                        let x = self.regs[rrogram(&mut self.process, self.pc + 5, 1) as usize] as usize;
                        let y = self.regs[rrogram(&mut self.process, self.pc + 6, 1) as usize] as usize;

                        for line in 0..h {
                            unsafe { RAM[dst + 0x960*y + 0x960*line + x*3 .. dst + 0x960*y + 0x960*line + x*3 + w*3].copy_from_slice(&RAM[src + w*3*line .. src + w*3*line + w*3]) }
                        }

                        self.pc += 4;
                    }
                    else {
                        self.process.as_mut().unwrap().exit(exit::UNAUTHORIZED_INSTRUCTION);
                    }
                }

                _ => {}
            }
            self.pc += 1;

            if self.process.as_ref().unwrap().state == ProcessState::Terminate {
                proc_index = self.terminate_process(proc_index)
            }
        }
    }
}
