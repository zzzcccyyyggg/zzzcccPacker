#include<stdio.h>
#include<string.h>
int main(){
    char secret[50] = "z2zccc_s_s3cret";
    printf("please input zzzccc secret:");
    int number = 0;
    scanf("%d",&number);
    if(strlen(secret) == number){
        printf("nice man!"); 
    } 
    else{
        printf("no");
    }

}