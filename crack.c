#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *plainText = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");
    if (!hashFile) {
        perror("Can't open hash file");
        free(plainText);
        exit(1);
    }

    char word[HASH_LEN];
    // Loop through the hash file, one line at a time.
    while (fgets(word, HASH_LEN, hashFile)) {
        word[strcspn(word, "\n")] = '\0';

        if (strcmp(word, plainText) == 0) {
            free(plainText);
            fclose(hashFile);
            return strdup(word);
        }
    }

    // Attempt to match the hash from the file to the
    // hash of the plaintext.

    // If there is a match, you'll return the hash.
    // If not, return NULL.

    // Before returning, do any needed cleanup:
    //   Close files?
    //   Free memory?
    fclose(hashFile);
    free(plainText);
    // Modify this line so it returns the hash
    // that was found, or NULL if not found.
    return NULL;
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    FILE *dictFile = fopen(argv[2], "r");
    if (!dictFile) {
        perror("Error opening dictionary file");
        fclose(dictFile);
        exit(1);
    }

    int hashesCrackedCount = 0;
    char word[PASS_LEN];

    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    while (fgets(word, PASS_LEN, dictFile)) {
        char *nl = strchr(word, '\n');
        if (nl) *nl = '\0';

        // Check if word hash matches any hash in the hash file
        char *matchedHash = tryWord(word, argv[1]);
        if (matchedHash != NULL) {
            printf("%s %s\n", matchedHash, word);
            free(matchedHash);
            hashesCrackedCount++;
        }
    }
    // If we got a match, display the hash and the word. For example:
    //   5d41402abc4b2a76b9719d911017c592 hello
    
    // Close the dictionary file.
    fclose(dictFile);

    // Display the number of hashes that were cracked.
    printf("Total hashes cracked: %d\n", hashesCrackedCount);

    return 0;
}