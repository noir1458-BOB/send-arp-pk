#include "get-my-mac.h"
#include <fstream>
#include <regex>

std::string Get_my_mac(std::string interface){
    std::ifstream iface("/sys/class/net/" + interface + "/address");
    std::string str((std::istreambuf_iterator<char>(iface)), std::istreambuf_iterator<char>());
    if (str.length() > 0) {
        // 마지막 개행문자 제거
        if (str.back() == '\n') {
            str.pop_back();
        }
        return str;
    }
    return "00:00:00:00:00:00";
}

//https://yogyui.tistory.com/entry/CLinux%EC%97%90%EC%84%9C-%EB%84%A4%ED%8A%B8%EC%9B%8C%ED%81%AC-%EC%96%B4%EB%8C%91%ED%84%B0-MAC-Address-%EA%B0%80%EC%A0%B8%EC%98%A4%EA%B8%B0