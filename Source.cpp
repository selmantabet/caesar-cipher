/*Selman Tabet (@selmantabet - https://selman.io/) - UIN 724009859
ECEN-449 Project - Part 1: Caesar Cipher Implementation

This is a program that takes a text file containing lines to be encrypted
or decrypted using the Caesar Cipher algorithm. The lines are separated by 
empty lines i.e. each line must be followed by 2 newline chars.
The encrypted_files and ingest_files arrays are where one could input a 
comma-separated list of text files to read from.
The encrypt_rotations consists of the Caesar shifts to be done for each ingest
file, and thus, the encrypt_rotations and ingest_files arrays are meant to
be the same in size.

All characters processed throughout the program must be ASCII printable characters.
Those take up the range [32 - 125] of the ASCII code.

Developed using Visual Studio Community 2019
Tested on Windows 10 Pro x64 19042.906 (20H2)*/


#include <errno.h> //For status handler
#include <stdio.h>
#include <stdlib.h> //For exit() function
#include <assert.h>
#include <ctype.h> //For ASCII check
#include <iostream> //For exit prompt.

//This definition is needed to handle multiple files.
#define length(array) ((sizeof(array)) / (sizeof(array[0])))


/*-------- GLOBAL VARS -------*/

//Iterator section.
int i; //The intake/dump iterator.
int j; //The result buffer iterator.

//Buffers and value dumps.
int shifts; //Number of shifts to be done. Direction-agnostic.
int intermediate; //Stores shifted character values post-rotation.
char intake[128]; //Input buffer for all incoming fscanf operations.
char shift_buffer[128]; //To insert number chars for atoi() to determine shifts.
char result[128]; //Result string.

//File-related variables. Feel free to add more as needed.
const char* encrypted_files[] = { "em_block1.txt", "em_block2.txt", "em_block3.txt", "em_extra.txt", "em_test.txt" };
const char* ingest_files[] = { "ingest.txt" }; //Modify this along with encrypt_rotations[] as needed.
int encrypt_rotations[] = {-49}; //Negative = Left rotation, Positive = Right rotation.
FILE* fptr; //Initialize file pointer.
errno_t err; //Status handler for fopen operation. 

/*----- END OF GLOBAL VARS ----*/


void welcome() {
    printf("-----------------------------------------\n");
    printf("Caesar Cipher Application by Selman Tabet\n");
    printf("-----------------------------------------\n");
    printf("------------https://selman.io/-----------\n");
    printf("-----------------------------------------\n");
}

void init() { //Initialize char buffers with NULL characters.
    for (int l = 0; l < sizeof(intake); l++) intake[l] = '\0'; 
    for (int m = 0; m < sizeof(result); m++) result[m] = '\0';
    for (int n = 0; n < sizeof(shift_buffer); n++) shift_buffer[n] = '\0';
}

char rotate_right(char input, int shift) {
    intermediate = ((int)input + (shift % 94)); //Right shift.
    /*First case is when the intermediate is already within the printable ASCII range
    in which no further mod calculations need to be done. Second case is when the intermediary
    goes beyond the printable range, this is where the remainder is taken out and a 32
    buffer is added to skip the ASCII control character range.*/
    /*Explicit typecast char to int for safer handling, then convert to unsigned ASCII char
    since unsigned char can extend to 255 instead of +-127 i.e. compliant with the output here.*/
    if ((intermediate / 126) == 0) return (unsigned char)intermediate;
    else return (unsigned char)((intermediate % 126) + 32);
}

char rotate_left(char input, int shift) {
    intermediate = ((int)input + (94 - (shift % 94))); //Left shift, AKA 94 minus right shift.
    //Same procedure as explained in the right shift function.
    if ((intermediate / 126) == 0) return (unsigned char)intermediate;
    else return (unsigned char)((intermediate % 126) + 32);
}



void encryptor() {
    printf("------------------------\n");
    printf("-------ENCRYPTION-------\n");
    printf("------------------------\n");
    for (int k = 0; k < length(ingest_files); k++) {
        init(); //Initialize buffers.
        if ((err = fopen_s(&fptr, ingest_files[k], "r")) != 0) {
            printf("File not found.\n");
            exit(1); //Program exits if file pointer returns NULL.
        }
        printf("------------------------\n");
        printf("Processing file: %s \n", ingest_files[k]);
        printf("------------------------\n");
        //Reads text until newline is encountered, using regex.
        while (fscanf_s(fptr, "%[^\n]", intake, sizeof(intake)) == 1) { //Return 1 means buffer is loaded.
            if ((intake[0] == '\n') || (intake[0] == '\0') || intake[1] == '\0') continue; //Empty line.
            else {
                printf("Ingest message: %s \n", intake);
                if (encrypt_rotations[k] < 0) { //Left rotation/shift mode.
                    result[0] = '~'; result[1] = '~'; //Double tilde for left rotation.
                    snprintf(shift_buffer, sizeof(shift_buffer), "%d", abs(encrypt_rotations[k]));
                    j = 0;
                    while (shift_buffer[j] != '\0') {
                        result[j + 2] = shift_buffer[j]; j++;
                    }
                    result[j + 2] = '~'; j++; //Public key sequence complete.
                    i = 0; j += 2; //Sync j to the currently targeted result buffer index.
                    printf("Rotating %s time(s) to the left.\n", shift_buffer);
                    //Loop as long as we don't hit a NULL, a newline or a non-printable ASCII value.
                    while ((intake[i] != '\0') && (intake[i] != '\n') && ((intake[i] < 127) && (intake[i] > 31))) {
                        assert(isascii(intake[i]) && "Detected a non-ASCII char. Abort.\n"); //Ensure ASCII char.
                        result[j] = rotate_left(intake[i], abs(encrypt_rotations[k]));
                        i++; j++;
                    }
                    printf("Encrypted message: %s \n\n", result); //Print complete message.
                    init(); //Reset buffers before continuing to the next iteration.
                    fgets(intake, sizeof(intake), fptr); fgets(intake, sizeof(intake), fptr); //Skip a line.
                }
                else if (encrypt_rotations[k] > 0) { //Right rotation/shift mode.
                    result[0] = '~';
                    snprintf(shift_buffer, sizeof(shift_buffer), "%d", abs(encrypt_rotations[k]));
                    j = 0;
                    while (shift_buffer[j] != '\0') {
                        result[j + 1] = shift_buffer[j]; j++;
                    }
                    result[j + 1] = '~'; j++; //Public key sequence complete.
                    i = 0; j++; //Sync j to the currently targeted result buffer index.
                    printf("Rotating %s time(s) to the right.\n", shift_buffer);
                    //Loop as long as we don't hit a NULL, a newline or a non-printable ASCII value.
                    while ((intake[i] != '\0') && (intake[i] != '\n') && ((intake[i] < 127) && (intake[i] > 31))) {
                        assert(isascii(intake[i]) && "Detected a non-ASCII char. Abort.\n"); //Ensure ASCII char.
                        result[j] = rotate_right(intake[i], abs(encrypt_rotations[k]));
                        i++; j++;
                    }
                    printf("Encrypted message: %s \n\n", result); //Print complete message.
                    init(); //Reset buffers before continuing to the next iteration.
                    fgets(intake, sizeof(intake), fptr); fgets(intake, sizeof(intake), fptr); //Skip a line.
                }
                else {
                    printf("Error parsing ingest text. Please ensure correct format.\n");
                    printf("Diagnostic Info:\n Error at file %s \n", ingest_files[k]);
                    printf("This line -----> %s  \n go fix fast pl0x :( \n", intake);
                    exit(1);
                }

            }
            printf("--------------------\n");
        }

        //End-of-file, for when all works smoothly.
        if (feof(fptr)) (printf("EOF reached.\n\n"));
        //Error scenario.
        else {
            printf("Error. Read interrupted.\n");
            printf("Diagnostic Info:\n Interrupted at file %s \n", ingest_files[k]);
        }
        printf("--------------------\n");
        fclose(fptr);
    }
}

void decryptor() {
    printf("------------------------\n");
    printf("-------DECRYPTION-------\n");
    printf("------------------------\n");
    for (int k = 0; k < length(encrypted_files); k++) {
        init(); //Initialize buffers.
        if ((err = fopen_s(&fptr, encrypted_files[k], "r")) != 0) {
            printf("File not found.\n");
            exit(1); //Program exits if file pointer returns NULL.
        }
        printf("------------------------\n");
        printf("Processing file: %s \n", encrypted_files[k]);
        printf("------------------------\n");
        //Reads text until newline is encountered, using regex.
        while (fscanf_s(fptr, "%[^\n]", intake, sizeof(intake)) == 1) { //Return 1 means buffer is loaded.
            if ((intake[0] == '\n') || (intake[0] == '\0') || intake[1] == '\0') continue; //Empty line.
            else {
                printf("Encrypted message: %s \n", intake);
                if (intake[1] == '~') { //Left rotation/shift detected. Decrypt by right rotation.
                    i = 2;
                    while (intake[i] != '~') {
                        shift_buffer[i - 2] = intake[i]; //We know that shift chars start at index 2.
                        i++;
                    }
                    i++; j = 0;
                    shifts = atoi(shift_buffer); //Convert shift string to an int.
                    printf("Rotating %i time(s) to the right.\n", shifts);
                    //Loop as long as we don't hit a NULL, a newline or a non-printable ASCII value.
                    while ((intake[i] != '\0') && (intake[i] != '\n') && ((intake[i] < 127) && (intake[i]  > 31))){
                        assert(isascii(intake[i]) && "Detected a non-ASCII char. Abort.\n"); //Ensure ASCII char.
                        result[j] = rotate_right(intake[i], shifts);
                        i++; j++;
                    }
                    printf("Decrypted message: %s \n\n", result);
                    init(); //Reset buffers before continuing to the next iteration.
                    fgets(intake, sizeof(intake), fptr); fgets(intake, sizeof(intake), fptr); //Skip a line.
                }
                else if (intake[0] == '~') { //Right rotation/shift detected. Decrypt by left rotation.
                    i = 1;
                    while (intake[i] != '~') {
                        shift_buffer[i - 1] = intake[i]; //We know that shift chars start at index 1.
                        i++;
                    }
                    i++; j = 0;
                    shifts = atoi(shift_buffer); //Convert shift string to an int.
                    printf("Rotating %i time(s) to the left.\n", shifts);
                    //Loop as long as we don't hit a NULL, a newline or a non-printable ASCII value.
                    while ((intake[i] != '\0') && (intake[i] != '\n') && ((intake[i] < 127) && (intake[i]  > 31))) {
                        assert(isascii(intake[i]) && "Detected a non-ASCII char. Abort.\n"); //Ensure ASCII char.
                        result[j] = rotate_left(intake[i], shifts);
                        i++; j++;
                    }
                    printf("Decrypted message: %s \n\n", result);
                    init(); //Reset buffers before continuing to the next iteration.
                    fgets(intake, sizeof(intake), fptr); fgets(intake, sizeof(intake), fptr); //Skip a line.
                }
                else {
                    printf("Error parsing ingest text. Please ensure correct format.\n");
                    printf("Diagnostic Info:\n Error at file %s \n", encrypted_files[k]);
                    printf("This line -----> %s  \n go fix fast pl0x :( \n", intake);
                    exit(1);
                }

            }
            printf("--------------------\n");
        }

        //End-of-file, for when all works smoothly.
        if (feof(fptr)) (printf("EOF reached.\n\n"));
        //Error scenario.
        else {
            printf("Error. Read interrupted.\n"); 
            printf("Diagnostic Info:\n Interrupted at file %s \n", encrypted_files[k]);
        }
        printf("--------------------\n");
        fclose(fptr);
    }
}

int main() {

    welcome();

    if (length(ingest_files) != length(encrypt_rotations)) {
        printf("Bad entry on ingest/rotations arrays.\n"); exit(1);
    }
    
    if (length(ingest_files) > 0) {
        encryptor();
        printf("Encryption complete. \n");
    }
    else printf("No ingest files detected. Encryption skipped.\n");

    printf("\n");

    if (length(encrypted_files) > 0) { 
        decryptor();
        printf("Decryption complete. \n");
    }
    else printf("No encrypted files detected. Decryption skipped.\n");

    printf("----------------- End of program ---------------\n");
    printf("Press Enter to exit. \n");
    getchar(); //Wait for button press.

    return 0;
}