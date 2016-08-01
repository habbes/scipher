/*

Clement 'Habbes' Habinshuti

This is a simple file encryption program
it is based on the lectures given by Dr. Lovett
at ANU on introduction to cryptography.
The program implements a simple stream-cipher
algorithm based on his examples

this is a corrected version of scipher-old.c
obsolete and test functions have also been omitted

in this windows version regex.h and related
functions are omitted, so even the functions
checking whether the key is valid are not
available
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
//#include <regex.h>

//callback used for the combiner and feedback functions
typedef unsigned char (*register_cb) (unsigned char *reg, int unitsize);

//FUNCTION PROTOTYPES

int file_exists(char *fname);
int copy(char *sname, char *dname);
unsigned char extract_bits(unsigned char byte, int count, int pos);
unsigned char get_bit(unsigned char byte, unsigned char pos);
unsigned char get_data_bit(unsigned char *data, int pos, int unitsize);
unsigned char encode_key_char(char c, char *alphabet, int length);
int encode_key(char *key, unsigned char *dest, char *alphabet, int alpha_length);
int compress_key(unsigned char *source, int ssize, unsigned char *dest, int dsize, int slength);
unsigned char shiftl_append(unsigned char byte, int count, unsigned char append);
void shiftl_data_append(unsigned char *data, int count, unsigned char append, 
	int datalenth, int unitsize);
int encrypt(char *filename, unsigned char *reg, int reglength, int unitsize, 
	register_cb feedback, register_cb combiner);


//FUNCTION DEFINITIONS


//check whether a file exists
int file_exists(char * fname)
{
	FILE * f = fopen(fname,"r");
	if (!f){
		if (errno == ENOENT)return 0;
	}
	fclose(f);
	return 1;
}

//copy one file to another and return the size of the content copied in bytes
//return -1 on error
int copy(char * sname, char * dname)
{
	FILE * source = fopen(sname,"r");
	FILE * dest = fopen(dname,"w");
	int size = 0;
	if (!source || !dest) return -1;
	int cur = fgetc(source);
	//had initally done cur != EOF, works too
	while (!feof(source)){
		fputc(cur,dest);
		size++;
		cur = fgetc(source);
	}
	fclose(source);
	fclose(dest);
	return size;
}

/**
 * extract a certain number of bits starting at the given
 * position of the given byte and then return the value of
 * the extracted bits.
 * pos is the 0-indexed position of the first bit to extract
 * count is the number of bits to extract starting from pos
 */
unsigned char extract_bits(unsigned char byte, int count, int pos)
{
	/* make a byte with all 0 bits except for the bits
	at the same pos as the bits to extract
	we need them to be 1 to work with AND */
	unsigned char operand = (1 << count) - 1;
	operand <<= pos;
	unsigned char extracted = byte & operand;

	/* return the value of the extracted bits with
	the trailing 0's stripped out */
	return extracted >> pos;
}

/**
 * get the bit at the specified 0-based position of the
 * given byte.
 */
unsigned char get_bit(unsigned char byte, unsigned char pos)
{
	//power of 2 used to check the bit at the given position
	unsigned char tester = (unsigned char) 1 << pos;
	unsigned char res = byte & tester;
	return (res == tester)? (unsigned char) 1 : (unsigned char) 0;
}



/**
 * get the bit at the given 0-indexed position in the given array
 * of data.
 * takes it as if all the bits of all the bytes of the data
 * were laid out sequentially and then picks out the one bit at pos
 * unitsize is the size in bits of each unit of data
 */
unsigned char get_data_bit(unsigned char *data, int pos, int unitsize)
{
	/* index of the byte or data unit in the array from which bit
	 will be extracted */
	int bytepos = pos / unitsize;
	/* index of the bit in the given byte */
	int bitpos = (pos % unitsize);

	unsigned char byte = data[bytepos];
	return get_bit(byte, bitpos);
}


/**
 * returns a number indicating the index of c in alphabet,
 * length is the size of alphabet, if the returned value is equal
 * to length, then the character could be found in the keyspace
 */
unsigned char encode_key_char(char c, char* alphabet, int length)
{
	unsigned char i = 0;
	while(alphabet[i] != c && i < length) i++;
	return i;
}

/**
 * encodes the null terminated key into numbers based on the alphabet
 * and stores it on dest
 * returns the number of chars encoded, if this is greater than the
 * key's length, an error may have occured (key not null terminated)
 */
int encode_key(char *key, unsigned char *dest, char *alphabet, int alpha_length)
{
	int i = 0;
	while(key[i] != '\0'){
		dest[i] = encode_key_char(key[i], alphabet, alpha_length);
		i++;
	}
	return i;

}

/**
 * compress data that uses only ssize bits per byte to
 * data that uses dsize bits per byte
 * slength is the length of the source
 */
int compress_key(unsigned char *source, int ssize, unsigned char *dest, int dsize, int slength)
{
	if(dsize < ssize) {
		//this is an error
		return -1;
	}

	//index of current source byte
	int i = 0;
	//index of dest byte
	int j = 0;
	//current working byte
	unsigned char cbyte;
	//number of significant bits remaining in current source byte
	int sbits = ssize;
	//number of bits needed to fill the current source byte
	// to use up all dsize bits
	int needed = dsize - sbits;
	//filler bits extracted from the next source byte
	unsigned char copied;

	while(i < slength){
		if(sbits == 0) {
			//if this byte has no significant data bits, skip it and
			// go to next byte
			sbits = ssize;
			i++;
			continue;
		}


		cbyte = source[i];
		needed = dsize - sbits;

		//extract needed bits from next source byte
		copied = extract_bits(source[i + 1], needed, 0);

		//append the copied bits to the right end of current byte
		cbyte = shiftl_append(cbyte, needed, copied);

		//store in destination
		dest[j] = cbyte;
		j++;

		//strip the stolen bits of the next byte
		source[i + 1] >>= needed;

		//since 'needed' bits have been extracted from the next byte,
		// it has less signigicant bits compared to the gaining byte
		sbits -= dsize - ssize;

		i++;
	}

	//returns length of destination
	return j;
}

/**
 * shift a byte to the left count times and appends the given byte
 * at the given byte at the less-signigicant (right) end. If the
 * byte to append takes more than count bits, the least significant
 * (right) count bits will be considered and the rest discarded,
 * returns the new byte
 */
unsigned char shiftl_append(unsigned char byte, int count, unsigned char append)
{
	//shift byte
	byte <<= count;

	//trim leading excess bits from append
	if(append >= (1 << count)){
		//if append is larger than what can
		// be represented with count bits,
		// only the last count bits are taken
		append %= count;
	}
	byte += append;
	return byte;
}

/**
 * shift all the data in the array count times to the left
 * and append the desired byte on the last element of the array
 * datalength is the number of elements in the array
 * unitsize is the size in bits of each element of the array
 */
void shiftl_data_append(unsigned char *data, int count, unsigned char append, int datalength, int unitsize)
{
	int i = 0;

	//value of bits borrowed from next byte
	unsigned char extracted;

	for(i = 0; i < datalength - 1; i++){
		//do not do the last element in the loop
		extracted = extract_bits(data[i + 1], count, unitsize - count);
		data[i] = shiftl_append(data[i], count, extracted);
	}

	//shift last element of the loop separately because
	// it's append byte is not extracted from next byte
	data[i] = shiftl_append(data[i], count, append);

}

/**
 * encrypts or decrypts the specified file,
 * this procedure is reversible: if the same register (key)
 * is provided for an encrypted file, the file will be decrypted
 * to its original
 *
 * filename is the name of the file to encrypt/decrypt
 * reg is the register, it is obtained by compressing the key
 * reglength is the length of the register
 * unitsize is the size in bits of each element of the register
 * feedback is the function that implements the register feedbkack function
 *   used to modify the register
 * combiner is the implementation of the combiner function which produces
 *   an encryption byte of of the register
 *
 * returns the number of bytes successfully encrypted/decrypted
 */
int encrypt(char *filename, unsigned char *reg, int reglength, int unitsize, register_cb feedback_cb, register_cb combiner_cb)
{
	FILE *source = fopen(filename, "r");
	if(!source){
		fprintf(stderr, "could not open source file\n");
		return 0;
	}

	char *tempbasename = "scipherencrtemp";
	char *tempname = malloc(strlen(tempbasename) + strlen(filename) + 1);
    strcpy(tempname, tempbasename);
	strcat(tempname, filename);

	FILE *temp = fopen(tempname, "w");
	if(!temp){
        fclose(source);
        free(tempname);
		fprintf(stderr, "could not create temp file\n");
		return 0;
	}

	int size = 0;
	//encryption byte created by running combiner and
	// feedback functions
	unsigned char enc_byte;
	//source byte coming in from the file
	unsigned char src_byte = fgetc(source);
	//temp storage for the result bit of combiner and feedback functions
	unsigned char res_bit;
	int i = 0;

	while(!feof(source)){
		enc_byte = 0;
		for(i = 0; i < unitsize; i++){
			//combiner gets a bit from the current state of the register
			//this bit will be used to encrypt the file byte
			res_bit = combiner_cb(reg, unitsize) % 2;
			//printf("cmb res %d\n", res_bit);

			//printf("current enc bit: %d", res_bit);
			enc_byte = shiftl_append(enc_byte, 1, res_bit);
			//feedback gets a bit from the current state of the register
			// this bit will be pushed onto the right of the shifted register
			// thus modifying the state of the register
			res_bit = feedback_cb(reg, unitsize) % 2;
            //printf("fbit %d", res_bit);
			//shift register
			shiftl_data_append(reg, 1, res_bit, reglength, unitsize);

		}

		//xor the created byte with the byte from the file

		enc_byte = enc_byte ^ src_byte;

		//write to tempfile;
		enc_byte = fputc(enc_byte, temp);

		size++;
		src_byte = fgetc(source);

	}


	fclose(source);
	fclose(temp);

	copy(tempname, filename);
	//delete temp
	remove(tempname);
    free(tempname);
	return size;
}

/**
 * example of a feedback function
 * produces a value as a result of operations on selected
 * bits of the register.
 * The result will be used to modify the state of the
 * register in the encrypt() function
 */
unsigned char feedback(unsigned char *reg, int unitsize)
{
	unsigned char a, b, c, d, e, f, g;
	a = get_data_bit(reg, 3, unitsize);
	b = get_data_bit(reg, 25, unitsize);
	c = get_data_bit(reg, 10, unitsize);
	d = get_data_bit(reg, 90, unitsize);
	e = get_data_bit(reg, 30, unitsize);
	f = get_data_bit(reg, 47, unitsize);
	g = get_data_bit(reg, 81, unitsize);

	return a + b + c * d + e * f * g;
}

/**
 * example of combiner function
 * gives the result of operations on selected bits of
 * the register, the result of which will be used to
 * produce a byte that used to encrypt a source byte
 */
unsigned char combiner(unsigned char *reg, int unitsize)
{
	unsigned char a, b, c, d, e, f, g;
	a = get_data_bit(reg, 67, unitsize);
	b = get_data_bit(reg, 52, unitsize);
	c = get_data_bit(reg, 26, unitsize);
	d = get_data_bit(reg, 95, unitsize);
	e = get_data_bit(reg, 39, unitsize);
	f = get_data_bit(reg, 76, unitsize);
	g = get_data_bit(reg, 82, unitsize);
	return a + b + c * d + e * f * g ;
}

/**
 * simple help message on the usage of the program
 * invoked when input errors occur
 */
void print_help()
{
	puts("");
	puts("usage: scipher <filename> <key>\n");
	printf("%-10s : name of the file to encrypt/decrypt\n", "<filename>");
	printf("%-10s : string of 6 to 16 characters in the alphabet", "<key>");
	printf(" [A-Za-z0-9_-]\n");
	puts("\nIf file is encrypted it will be decrypted and vice-versa");
	puts("");
}


int main(int argc, char *argv[])
{
	//run_tests();
	puts("");
	int errors = 0;

	//CHECKING INPUT ERRORS
	if(argc <= 2){

		fprintf(stderr, "Insufficient number of command parameters\n");
		print_help();
		return 1;

		errors++;
	}

	char *filename = argv[1];
	char *user_key = argv[2];
	


	//check file availability
	if(!file_exists(filename)){
		fprintf(stderr, "The specified file could not be found\n");
		errors++;
	}

	//pattern for a valid key
	/*
	//require regex
	char *key_patt = "^([A-Za-z0-9_-]{6,16})$";
	regex_t key_re;
	*/
	int res = 0;
	/*
	res = regcomp(&key_re, key_patt, REG_EXTENDED | REG_NEWLINE);
	if(res != 0){
		fprintf(stderr, "Regex error occured\n");
		errors++;
	}

	//check key validity
	res = regexec(&key_re, user_key, 0, NULL, 0);
	if(res == REG_NOMATCH){

		fprintf(stderr, "Invalid key\n");
		errors++;
	} else if (res != 0) {
		fprintf(stderr, "Regex error occured\n");
		errors++;
	}

	regfree(&key_re);
	*/
	//weak workaround for the missing regex
	if(strlen(user_key) > 16){
		fprintf(stderr, "Invalid key\n");
		errors++;
	}



	if(errors > 0){
		print_help();
		fprintf(stderr, "Input errors occured\n");
		return 1;
	}


	//NO INPUT ERRORS
	printf("please wait...\n");


	char *key_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
	int key_alphalength = strlen(key_alpha);
	int key_charsize = 6;
	int key_maxlength = 16;
	int byte_size = 8;

	//TODO: error if malloc fails
	//reserve space for the key and terminating byte
	char *key = malloc(key_maxlength + 1);
	//reserve space for the encoded key
	unsigned char *enc_key = malloc(key_maxlength);
	//the register will result from a compression of the key
	int reg_length = (key_charsize * key_maxlength) / byte_size;
	//reserve space for the register
	unsigned char *reg = malloc(reg_length);


    //ENCODE AND COMPRESS KEY
	strcpy(key, user_key);

	int i = 0;
	//fill empty chars in key with a char from the key alphabet
	for(i = strlen(user_key) ; i < key_maxlength; i++){
		key[i] = key_alpha[ (i) % key_maxlength];
	}
	key[key_maxlength] = '\0';

	encode_key(key, enc_key, key_alpha, key_alphalength);

    //compress key and store it to reg (register)
	compress_key(enc_key, key_charsize, reg, byte_size, key_maxlength);

    //ENCRYPT (this also decrypts if the file is encrypted with the same key)
    res = encrypt(filename, reg, reg_length, byte_size, feedback, combiner);

    printf("%d bytes of data encrypted/decrypted\n", res);



	//free malloc'd memory
	free(key);
	free(enc_key);
	free(reg);

	return 0;
}
