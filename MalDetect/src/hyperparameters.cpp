
#include "hyperparameters.h"

Hyperparameters::Hyperparameters(const string& confFile) {

    printf("Loading config file: %s ...\n", confFile.c_str());

    FILE * f = fopen(confFile.c_str(), "r");
    if(f==NULL){
        printf("open config file failed!\n");
        exit(0);
    }

    // Node/Tree
    fscanf(f, "Tree.maxDepth %d\n", &maxDepth);
    fscanf(f, "Tree.numRandomTests %d\n", &numRandomTests);
    fscanf(f, "Tree.numProjectionFeatures %d\n", &numProjectionFeatures);
    fscanf(f, "Tree.counterThreshold %d\n", &counterThreshold);

    // Forest
    fscanf(f, "Forest.numTrees %d\n", &numTrees);
    fscanf(f, "Forest.numEpochs %d\n", &numEpochs);
    fscanf(f, "Forest.useSoftVoting %d\n", &useSoftVoting);

    // Output
    fscanf(f, "Output.verbose %d\n", &verbose);

    // Classes
    fscanf(f, "Class.num %d\n", &class_num);
    int n;
    for(int i=0; i<class_num; i++){
        char *temp = (char *)malloc(15);
        fscanf(f, "Class.label%d %s\n", &n, temp);
        labels[i] = temp;
    }

    for(int i=0; i<class_num; i++){
        printf("%s ", labels[i]);
    }

    printf("Done.\n");
}
