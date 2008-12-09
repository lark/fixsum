/*
 * TP-Link WR941 V2 firmware checksum fixing tool.
 *
 * Copyright (C) 2008,2009 Wang Jian <lark@linux.net.cn>
 *
 * Note: This tool may only work in big endian system.
 *
 * This software is based on reverse engineering and variables are named
 * following the original ones deliberately (to compare assemble code)
 *
 * This software is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "md5.h"

/*
 * Content in these offset will be checked to verify firmware's integrity
 */
#define FW_OFFSET_VERSION		0x40	/* should be 0x09410002 */
#define FW_OFFSET_SIG			0x44	/* should be 0x2 */
#define	FW_OFFSET_MD5SUM_1		0x4c	/* 16 bytes */
#define FW_OFFSET_MD5SUM_2		0x60	/* 16 bytes */
#define FW_OFFSET_USE_LOADER_KEY	0x94	/* when set, bootloader key is used */

#define FW_FILENAME	"wr941n.bin"

char md5Key[16] = {
	0xdc, 0xd7, 0x3a, 0xa5, 0xc3, 0x95, 0x98, 0xfb,
	0xdd, 0xf9, 0xe7, 0xf4, 0x0e, 0xae, 0x47, 0x38,
};
char md5Key_bootloader[16] = {
	0x8c, 0xef, 0x33, 0x5b, 0xd5, 0xc5, 0xce, 0xfa,
	0xa7, 0x9c, 0x28, 0xda, 0xb2, 0xe9, 0x0f, 0x42,
};

char *uploadBuf;
int  uploadFileSize;
int  imageFd;

int isSysUpgradeNeedChecksum(void)
{
	return 1;
}

void openFirmwareImage(char *filename)
{
	int ret;

	imageFd = open(filename, O_RDWR);

	if (imageFd == -1) {
		printf("Can't open image file\n");
		exit(-1);
	}

	uploadFileSize = lseek(imageFd, 0, SEEK_END);
	if (uploadFileSize > 0x800000) {
		printf("Image is too large\n");
		exit(-1);
	}
	lseek(imageFd, 0, SEEK_SET);

	uploadBuf = (char *) malloc(uploadFileSize);
	if (uploadBuf == NULL) {
		printf("Unable to alloc buffer\n");
		exit(-1);
	}

	ret = read(imageFd, uploadBuf, uploadFileSize);
	if (ret != uploadFileSize) {
		printf("Read less than file length: %d/%d\n", ret, uploadFileSize);
		exit(-1);
	} else {
		printf("Read image: %d/%d\n", ret, uploadFileSize);
	}
}

char *getMd5Key_bootloader(void)
{
	return md5Key_bootloader;
}

char *getMd5Key(void)
{
	return md5Key;
}

char *uploadBufGet(void)
{
	return uploadBuf;
}

int uploadFileSizeGet(void)
{
	return uploadFileSize;
}

int md5_make_digest(char *csum, char *data, int size)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, data, size);
	MD5_Final(csum, &ctx);
}

int md5_verify_digest(char *csum, char *buff, int size)
{
	char result[16];
	int i;
	int ret;

	md5_make_digest(result, buff, size);

	printf("md5sum should be\t");
	for(i = 0; i < 16; i++)
		printf("%.2x", (unsigned char)result[i]);
	printf("\ncurrent is\t\t");
	for(i = 0; i < 16; i++)
		printf("%.2x", (unsigned char)csum[i]);
	printf("\n");

	ret = strncmp(result, csum, 0x10) == 0 ? 1 : 0;
	strncpy(csum, result, 16);

	return ret;
}

/*
 * Although there 2 MD5 sum in the header, only first one is used.
 *
 * The algorithm is simple:
 *
 * 1. create an firmware image which has correct signatures
 * 2. padding first MD5 sum in the header with seed (md5Key or
 *    md5Key_bootloader)
 * 3. calculate the MD5 sum of whole image
 * 4. fill the first MD5 sum with the calculated one
 */
int upgradeFirmware(char *buff, int size)
{
	int csum[4];
	int *salt;
	char *errstr;

	if (size - 0x30000 > 0x7d0000)
		goto err;

#if 0
	if (isSysUpgradeNeedChecksum() == 0)
		goto check_version;
#endif

check_version:
	if (*(int *)(buff + FW_OFFSET_VERSION) != ntohl(0x09410002)) {
		errstr = "Version not match";
		goto err;
	}

check_sig:
	if (*(int *)(buff + FW_OFFSET_SIG) != ntohl(0x2)) {
		errstr = "Signature not match";
		goto err;
	}

check_md5sum:
	csum[0] = * (int *) (buff + FW_OFFSET_MD5SUM_1);
	csum[1] = * (int *) (buff + FW_OFFSET_MD5SUM_1 + 4);
	csum[2] = * (int *) (buff + FW_OFFSET_MD5SUM_1 + 8);
	csum[3] = * (int *) (buff + FW_OFFSET_MD5SUM_1 + 12);

	if (*(int *)&buff[FW_OFFSET_USE_LOADER_KEY] == 0)
		salt = (int *)getMd5Key();
	else
		salt = (int *)getMd5Key_bootloader();

	* (int *) (buff + FW_OFFSET_MD5SUM_1)		= salt[0];
	* (int *) (buff + FW_OFFSET_MD5SUM_1 + 4)	= salt[1];
	* (int *) (buff + FW_OFFSET_MD5SUM_1 + 8)	= salt[2];
	* (int *) (buff + FW_OFFSET_MD5SUM_1 + 12)	= salt[3];

	if (!md5_verify_digest((char *)csum, buff, size)) {
		* (int *) (buff + FW_OFFSET_MD5SUM_1)		= csum[0];
		* (int *) (buff + FW_OFFSET_MD5SUM_1 + 4)	= csum[1];
		* (int *) (buff + FW_OFFSET_MD5SUM_1 + 8)	= csum[2];
		* (int *) (buff + FW_OFFSET_MD5SUM_1 + 12)	= csum[3];

		printf("Fixing... ");
		lseek(imageFd, 0, SEEK_SET);
		write(imageFd, buff, size);
		printf("done.\n");
	}
	close(imageFd);

#if 0
	if (*(int *)(buff + FW_OFFSET_90) == 0
		&& *(int *)(buff + FW_OFFSET_94) == 0) {
		/*
		 * Normal upgrade
                 */
		ret = ucUpdateSysAppFile(size, buff, 0);
	} else {
		/*
		 * Upgrade kernel/rootfs/config
		 */
		ret = ucUpdateSysAppFile(size + 0xFE00, buff + 0x200, 1)
	}

#endif

	return 1;

err:
	printf("%s\n", errstr);
	return 0;
}

int main(int argc, char **argv)
{
	unsigned char *buff;
	int size;

	openFirmwareImage(FW_FILENAME);

	buff = uploadBufGet();
	size = uploadFileSizeGet();

	if (size == 0)
		exit(-1);

	upgradeFirmware(buff, size);
}
