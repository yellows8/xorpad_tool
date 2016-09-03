#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>

void print_hexdump(unsigned char *buf, unsigned int bufsz)
{
	unsigned int pos, curpos, blocksz;

	blocksz = 0x10;
	for(pos=0; pos<bufsz; pos+=0x10)
	{
		if(bufsz - pos < 0x10)blocksz = bufsz - pos;

		printf("%08x: ", pos);
		for(curpos=0; curpos<0x10; curpos++)
		{
			if((curpos & 1) == 0 && curpos > 0)printf(" ");
			if(curpos<blocksz)
			{
				printf("%02x", buf[pos + curpos]);
			}
			else
			{
				printf("  ");
			}
		}
		printf("  ");

		for(curpos=0; curpos<blocksz; curpos++)
		{
			if(isprint(buf[pos + curpos]))
			{
				printf("%c", buf[pos + curpos]);
			}
			else
			{
				printf(".");
			}
		}

		printf("\n");
	}
	printf("\n");
}

int check_bl(unsigned int value, int arm_mode)
{
	if(arm_mode)//thumb
	{
		if((value>>13) == 0x7 && ((value>>11) & 0x3) != 0)return 1;//bl(x)
	}
	else//arm
	{
		if(((value>>24) & 0xf) == 0xb)return 1;//bl
		if((value>>25) == 0x7d)return 1;//blx
	}

	return 0;
}

int xor_multiplefiles(char *infn_prefix, char *outfn_prefix, char *stripinprefix, char *xorfn, int disasm)
{
	unsigned int xor_sz = 0, in_sz = 0, sz = 0;
	unsigned int pos = 0;
	size_t readsz = 0;
	unsigned char *inbuf, *xorbuf;

	struct stat filestats;
	struct dirent *dir_entry;
	DIR *scandir;
	FILE *finput, *fxor, *fout;
	char infn[256];
	char outfn[256];
	char dirent_fn[256];
	char scandirpath[256];
	char inputprefix_filename[256];
	char sys_str[256];

	memset(infn, 0, 256);
	memset(outfn, 0, 256);
	memset(dirent_fn, 0, 256);
	memset(scandirpath, 0, 256);
	memset(inputprefix_filename, 0, 256);

	if(!strchr(infn_prefix, '/'))
	{
		strncpy(scandirpath, "./", 255);
		strncpy(inputprefix_filename, infn_prefix, 255);
	}
	else
	{
		strncpy(scandirpath, infn_prefix, strrchr(infn_prefix, '/') - infn_prefix + 1);
		strncpy(inputprefix_filename, strrchr(infn_prefix, '/') + 1, 255);
	}

	if(stat(xorfn, &filestats)==-1)
	{
		printf("failed to stat %s\n", xorfn);
		return 1;
	}
	xor_sz = filestats.st_size;

	xorbuf = (unsigned char*)malloc(xor_sz);
	if(xorbuf==NULL)
	{
		printf("failed to alloc mem.\n");
		return 2;
	}
	memset(xorbuf, 0, xor_sz);

	fxor = fopen(xorfn, "rb");
	readsz = fread(xorbuf, 1, xor_sz, fxor);
	fclose(fxor);

	if(readsz!=xor_sz)
	{
		printf("failed to read xor file\n");
		free(xorbuf);
		return 2;
	}

	scandir = opendir(scandirpath);
	if(scandir==NULL)
	{
		printf("failed to open directory: %s\n", scandirpath);
		free(xorbuf);
		return 1;
	}

	while((dir_entry = readdir(scandir)))
	{
		if(strncmp(dir_entry->d_name, inputprefix_filename, strlen(inputprefix_filename)))continue;
		if(strncmp(&dir_entry->d_name[strlen(dir_entry->d_name)-4], ".bin", 4))continue;

		memset(dirent_fn, 0, 256);
		strncpy(dirent_fn, dir_entry->d_name, 255);

		memset(infn, 0, 256);
		snprintf(infn, 255, "%s%s", scandirpath, dirent_fn);

		memset(&dirent_fn[strlen(dirent_fn)-4], 0, 4);

		if(stripinprefix[0]==0)
		{
			memset(outfn, 0, 256);
			snprintf(outfn, 255, "%s%s%s.xor", scandirpath, outfn_prefix, dirent_fn);
		}
		else
		{
			if(strncmp(dir_entry->d_name, stripinprefix, strlen(stripinprefix))==0)
			{
				memset(outfn, 0, 256);
				snprintf(outfn, 255, "%s%s%s.xor", scandirpath, outfn_prefix, &dirent_fn[strlen(stripinprefix)]);
			}	
			else
			{
				memset(outfn, 0, 256);
				snprintf(outfn, 255, "%s%s%s.xor", scandirpath, outfn_prefix, dirent_fn);
			}
		}

		printf("processing %s, outfn %s\n", infn, outfn);

		if(stat(infn, &filestats)==-1)
		{
			printf("failed to stat %s\n", infn);
			closedir(scandir);
			free(xorbuf);
			return 1;
		}
		in_sz = filestats.st_size;

		sz = xor_sz;
		if(in_sz < sz)sz = in_sz;

		inbuf = (unsigned char*)malloc(sz);
		if(inbuf==NULL)
		{
			printf("failed to alloc mem.\n");
			closedir(scandir);
			free(xorbuf);
			return 2;
		}
		memset(inbuf, 0, sz);
		
		finput = fopen(infn, "rb");
		readsz = fread(inbuf, 1, sz, finput);
		fclose(finput);

		if(readsz!=sz)
		{
			printf("failed to read input file\n");
			closedir(scandir);
			free(xorbuf);
			free(inbuf);
			return 2;
		}

		for(pos=0; pos<sz; pos++)inbuf[pos] ^= xorbuf[pos];

		fout = fopen(outfn, "wb");
		fwrite(inbuf, 1, sz, fout);
		fclose(fout);
		free(inbuf);

		if(disasm)
		{
			memset(&outfn[strlen(outfn)-4], 0, 4);

			printf("disassembling %s.xor to %sxor_ARM.s...\n", outfn, outfn);
			memset(sys_str, 0, 256);
			snprintf(sys_str, 255, "arm-eabi-objdump -D -b binary -m arm %s.xor > %sxor_ARM.s", outfn, outfn);
			system(sys_str);
			printf("\n");

			printf("disassembling %s.xor to %sxor_THUMB.s...\n", outfn, outfn);
			memset(sys_str, 0, 256);
			snprintf(sys_str, 255, "arm-eabi-objdump -D -b binary -m arm -M force-thumb %s.xor > %sxor_THUMB.s", outfn, outfn);
			system(sys_str);
			printf("\n");
		}
	}

	closedir(scandir);
	free(xorbuf);

	return 0;
}

int main(int argc, char **argv)
{
	FILE *finput, *fxor, *ffill = NULL;
	struct stat filestats;
	int argi;
	unsigned int inoff = 0, insz = 0;
	unsigned int xoroff = 0, xorsz = 0;
	unsigned int filloff = 0;
	unsigned int pos;
	int disasm = 0, hexdump = 0, removebl = 0, cmp = 0, xormultiple = 0;
	int arm_mode = 0, disasm_mode = 0;

	int blocksz = 0;
	unsigned int val = 0;
	size_t readsz0, readsz1, readsz2 = 0;
	unsigned char *inbuf, *xorbuf, *outbuf, *fillbuf;
	unsigned int *inbuf32, *xorbuf32, *outbuf32;
	unsigned short *outbuf16, *fillbuf16, *xorbuf16;

	char infn[256];
	char stripinprefix[256];
	char shiftfn[256];
	char xorfn[256];
	char outfn[256];
	char fillfn[256];
	char sys_str[256];

	printf("xorpad_tool by yellows8\n");

	memset(infn, 0, 256);
	memset(stripinprefix, 0, 256);
	memset(shiftfn, 0, 256);
	memset(xorfn, 0, 256);
	memset(outfn, 0, 256);
	memset(fillfn, 0, 256);

	for(argi=1; argi<argc; argi++)
	{
		if(strncmp(argv[argi], "--infn=", 7)==0)strncpy(infn, &argv[argi][7], 255);
		if(strncmp(argv[argi], "--stripinprefix=", 16)==0)strncpy(stripinprefix, &argv[argi][16], 255);
		if(strncmp(argv[argi], "--shiftfn=", 10)==0)strncpy(shiftfn, &argv[argi][10], 255);
		if(strncmp(argv[argi], "--xorfn=", 8)==0)strncpy(xorfn, &argv[argi][8], 255);
		if(strncmp(argv[argi], "--outfn=", 8)==0)strncpy(outfn, &argv[argi][8], 255);
		if(strncmp(argv[argi], "--fillfn=", 9)==0)strncpy(fillfn, &argv[argi][9], 255);

		if(strncmp(argv[argi], "--inoff=", 8)==0)sscanf(&argv[argi][8], "%x", &inoff);
		if(strncmp(argv[argi], "--xoroff=", 9)==0)sscanf(&argv[argi][9], "%x", &xoroff);
		if(strncmp(argv[argi], "--insz=", 7)==0)sscanf(&argv[argi][7], "%x", &insz);
		if(strncmp(argv[argi], "--xorsz=", 8)==0)sscanf(&argv[argi][8], "%x", &xorsz);
		if(strncmp(argv[argi], "--filloff=", 10)==0)sscanf(&argv[argi][10], "%x", &filloff);

		if(strncmp(argv[argi], "--armmode=", 10)==0)
		{
			if(strncmp(&argv[argi][10], "arm", 3)==0)arm_mode = 0;
			if(strncmp(&argv[argi][10], "thumb", 5)==0)arm_mode = 1;
		}
		if(strncmp(argv[argi], "--disasmmode=", 13)==0)
		{
			disasm = 1;
			if(strncmp(&argv[argi][13], "arm", 3)==0)disasm_mode = 0;
			if(strncmp(&argv[argi][13], "thumb", 5)==0)disasm_mode = 1;
		}
		if(strncmp(argv[argi], "--hexdump", 9)==0)hexdump = 1;
		if(strncmp(argv[argi], "--removebl", 10)==0)removebl = 1;
		if(strncmp(argv[argi], "--cmp", 5)==0)cmp = 1;
		if(strncmp(argv[argi], "--xormultiple", 13)==0)xormultiple = 1;
	}

	if(infn[0]==0 || xorfn[0]==0)
	{
		printf("Usage:\n");
		printf("--infn=<fn> Input filename\n");
		printf("--xorfn=<fn> File to xor the input with\n");
		printf("--shiftfn=<fn> File to xor with the result of infile^xorfile\n");
		printf("--outfn=<fn> Filename to write the output xored data\n");
		printf("--fillfn=<fn> Overwrite all 2-byte zeros from fn with the data from final output\n");
		printf("--stripinprefix=<prefix> For --xormultiple, remove the specified prefix from the output filenames used from the input filenames.\n");
		printf("--xormultiple XOR multiple files, with --infn for the prefix fn input, and --outfn for the optional output fn prefix. Only .bin files contained in the dir specified by --infn are processed, the .bin extension is stripped from the output filenames. --outfn can be used to specify the output filenames prefix.\n");
		printf("--inoff=<hexoff> Input-file/shift-file offset (0 by default)\n");
		printf("--insz=<hexsz> Input-file/shift-file size (filesize by default)\n");
		printf("--xoroff=<hexoff> Xor-file offset (0 by default)\n");
		printf("--xorsz=<hexsz> Xor-file size (filesize by default)\n");
		printf("--filloff=<hexoff> Fill file offset(default is zero)\n");
		printf("--armmode=<arm|thumb> Select which ARM mode to use\n");
		printf("--disasmmode=<arm|thumb> Enable disasm with the chosen ARM mode\n");
		printf("--hexdump Hexdump the final output\n");
		printf("--removebl Clear areas in the final output where there's bl(x) instructions in the xor input\n");
		printf("--cmp Compare the fill file with the output\n");
		return 0;
	}

	if(xormultiple)return xor_multiplefiles(infn, outfn, stripinprefix, xorfn, disasm);

	finput = fopen(infn, "rb");
	fxor = fopen(xorfn, "rb");
	if(fillfn[0])ffill = fopen(fillfn, "rb");
	if(finput==NULL || fxor==NULL || (ffill==NULL && fillfn[0]))
	{
		if(finput)fclose(finput);
		if(fxor)fclose(fxor);
		if(ffill)fclose(ffill);
		printf("failed to open input files\n");
		return 1;
	}

	stat(infn, &filestats);
	if(insz==0)insz = filestats.st_size - inoff;

	stat(xorfn, &filestats);
	if(xorsz==0)xorsz = filestats.st_size - xoroff;

	if(insz<xorsz)
	{
		xorsz = insz;
	}
	else if(xorsz<insz)
	{
		insz = xorsz;
	}

	printf("inoff=%x, xoroff=%x, insz=%x, xorsz=%x\n", inoff, xoroff, insz, xorsz);

	inbuf = (unsigned char*)malloc(insz);
	outbuf = (unsigned char*)malloc(insz);
	xorbuf = (unsigned char*)malloc(xorsz);
	fillbuf = (unsigned char*)malloc(insz);
	if(inbuf==NULL || outbuf==NULL || xorbuf==NULL)
	{
		printf("failed to alloc mem.\n");
		free(inbuf);
		free(outbuf);
		free(xorbuf);
		free(fillbuf);

		fclose(finput);
		fclose(fxor);
		if(ffill)fclose(ffill);

		return 2;
	}

	inbuf32 = (unsigned int*)inbuf;
	xorbuf32 = (unsigned int*)xorbuf;
	outbuf32 = (unsigned int*)outbuf;
	outbuf16 = (unsigned short*)outbuf;
	fillbuf16 = (unsigned short*)fillbuf;
	xorbuf16 = (unsigned short*)xorbuf;
	memset(inbuf, 0, insz);
	memset(outbuf, 0, insz);
	memset(xorbuf, 0, xorsz);
	memset(fillbuf, 0, insz);

	if(fseek(finput, inoff, SEEK_SET) == -1)
	{
		printf("failed to seek to %x in input file.\n", inoff);

		free(inbuf);
		free(outbuf);
		free(xorbuf);
		free(fillbuf);

		fclose(finput);
		fclose(fxor);
		if(ffill)fclose(ffill);

		return 3;
	}

	if(fseek(fxor, xoroff, SEEK_SET) == -1)
	{
		printf("failed to seek to %x in xor file.\n", xoroff);

		free(inbuf);
		free(outbuf);
		free(xorbuf);
		free(fillbuf);

		fclose(finput);
		fclose(fxor);
		if(ffill)fclose(ffill);

		return 3;
	}

	if(ffill && fseek(ffill, filloff, SEEK_SET) == -1)
	{
		printf("failed to seek to %x in fill file.\n", filloff);

		free(inbuf);
		free(outbuf);
		free(xorbuf);
		free(fillbuf);

		fclose(finput);
		fclose(fxor);
		fclose(ffill);

		return 3;
	}

	readsz0 = fread(inbuf, 1, insz, finput);
	readsz1 = fread(xorbuf, 1, xorsz, fxor);
	if(ffill)readsz2 = fread(fillbuf, 1, insz, ffill);
	fclose(finput);
	fclose(fxor);
	if(ffill)fclose(ffill);

	if(readsz0!=insz || readsz1!=xorsz || (readsz2!=insz && ffill))
	{
		printf("reading failed.\n");

		free(inbuf);
		free(xorbuf);
		free(outbuf);
		free(fillbuf);

		return 3;
	}

	for(pos=0; pos<insz; pos++)
	{
		outbuf[pos] = inbuf[pos] ^ xorbuf[pos];
	}

	if(removebl)
	{
		if(!arm_mode)blocksz = 4;//arm
		if(arm_mode)blocksz = 2;//thumb
		for(pos=0; pos<insz/blocksz; pos++)
		{
			if(!arm_mode)val = xorbuf32[pos];//arm
			if(arm_mode)val = xorbuf16[pos];//thumb

			if(check_bl(val, arm_mode))
			{
				printf("clearing bl(x) @ final output %x(in %x/xor %x)\n", pos*blocksz, pos*blocksz + inoff, pos*blocksz + xoroff);
				if(!arm_mode)outbuf32[pos] = 0;//arm
				if(arm_mode)outbuf16[pos] = 0;//thumb
			}
		}

		printf("\n");
	}

	if(fillfn[0])
	{
		if(insz & 1)
		{
			printf("size must be u16-aligned.\n");
		}
		else
		{
			for(pos=0; pos<insz/2; pos++)
			{
				if(!cmp)
				{
					if(fillbuf16[pos])
					{
						if(outbuf16[pos]!=fillbuf16[pos])
						{
							printf("overwriting out with fill: out!=fill %x(in %x/xor %x): %x %x\n", pos*2, pos*2 + inoff, pos*2 + xoroff, outbuf16[pos], fillbuf16[pos]);
							outbuf16[pos] = fillbuf16[pos];
						}
					}
					else
					{
						printf("detected zeros @ fill %x(in %x/xor %x), using original out data\n", pos*2, pos*2 + inoff, pos*2 + xoroff);
					}
				}
				else
				{
					if(arm_mode)//thumb
					{
						if(check_bl(fillbuf16[pos], arm_mode))continue;
					}

					if(outbuf16[pos]!=fillbuf16[pos])printf("fill!=out: %x(in %x/xor %x/fill %x): %x %x\n", pos*2, pos*2 + inoff, pos*2 + xoroff, pos*2 + filloff, outbuf16[pos], fillbuf16[pos]);
				}
			}
		}
	}

	if(shiftfn[0])
	{
		if(!arm_mode)blocksz = 4;
		if(arm_mode)blocksz = 2;

		fxor = fopen(shiftfn, "rb");
		if(fxor)
		{
			fseek(fxor, inoff, SEEK_SET);
			readsz0 = fread(xorbuf, 1, insz, fxor);
			fclose(fxor);

			if(readsz0!=insz)
			{
				printf("reading shift file failed.\n");

				free(inbuf);
				free(xorbuf);
				free(outbuf);
				free(fillbuf);
				return 3;
			}

			for(pos=0; pos<insz/blocksz; pos++)
			{
				if(!arm_mode)val = outbuf32[pos];
				if(arm_mode)val = outbuf16[pos];

				if(val)
				{
					if(!arm_mode)outbuf32[pos] ^= xorbuf32[pos];
					if(arm_mode)outbuf16[pos] ^= xorbuf16[pos];
				}
			}
		}
		else
		{
			printf("failed to open %s\n", shiftfn);
		}
	}

	if(outfn[0])
	{
		fxor = fopen(outfn, "wb");
		fwrite(outbuf, 1, insz, fxor);
		fclose(fxor);
	}

	if(hexdump)
	{
		printf("\n");
		print_hexdump(outbuf, insz);
	}

	fflush(stdout);

	if(disasm)
	{
		memset(sys_str, 0, 256);
		snprintf(sys_str, 255, "arm-eabi-objdump -D -b binary --adjust-vma=0x%x -m arm%s %s", inoff, disasm_mode==1?" -M force-thumb":"", outfn);
		system(sys_str);
		printf("\n");
	}

	free(inbuf);
	free(xorbuf);
	free(outbuf);
	free(fillbuf);

	return 0;
}

