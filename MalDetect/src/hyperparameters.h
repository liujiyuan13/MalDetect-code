#ifndef HYPERPARAMETERS_H_
#define HYPERPARAMETERS_H_

#include <string>
using namespace std;

class Hyperparameters
{
 public:
    Hyperparameters();
    Hyperparameters(const string& confFile);

    // Online node
    int numRandomTests;
    int numProjectionFeatures;
    int counterThreshold;
    int maxDepth;

    // Online tree

    // Online forest
    int numTrees;
    int useSoftVoting;
    int numEpochs;

    // Output
    int verbose;

    // Classes
    int class_num;
    char * labels[15];
};

#endif /* HYPERPARAMETERS_H_ */
