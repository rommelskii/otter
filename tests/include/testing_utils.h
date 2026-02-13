#ifndef TESTING_UTILS_H
#define TESTING_UTILS_H

/**************************************
  * MACROS 
  ***************************************/

/**
@ EXPECT
* @brief Asserts a condition and prints the result and description of the test
* @param condition Boolean expression to be tested
* @param message Description to be printed alongside the result of the test
*/
#define EXPECT(condition, message) \
    do { \
        if (!(condition)) { \
            printf("\n[FAILED] %s\n", message); \
            printf("         at %s:%d\n", __FILE__, __LINE__); \
            tests_failed++; \
        } else { \
            printf("[PASSED] %s\n", message); \
        } \
    } while (0)

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__) 

#endif // TESTING_UTILS_H


