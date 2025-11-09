#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace std;

int main() {

   string str;

   cout << "enter input string: ";
   getline(cin, str);
   cout << str << endl << str [0] << endl;
    // if string starts or ends with null character, crash ex: "\0abcd" or "abcd\0"
    if(str[0] == 0 || str[str.length() - 1] == 0) {
        abort();
    }
    else {
        int count = 0;
        char prev_num = 'x';
        // crash if two numbers are consecutive ex: "ab[12]cd" or "[45]ef"
        while (count != str.length() - 1) {
            char c = str[count];
            if(c >= 48 && c <= 57) { // ASCII values for '0' to '9'
                if(c == prev_num + 1) {
                    abort();
                }
                prev_num = c;
            } 
            count++;
        }
    }
    
    return 0;
}