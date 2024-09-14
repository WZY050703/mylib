#include <iostream>
#include <fstream>
#include <random>
#include <ctime>
#include "mystr"
#include "myqueue"

#define COUT std::cout
#define ENDL std::endl

#define PLACEHOLDING char(26)                       // 删除占位符
#define ASEPARATOR char(30)                         // 小分隔符
#define BSEPARATOR char(127)                        // 大分隔符
char NAMESTRS[4][5] = {"ID", "int", "str", "time"}; // 防止const不准转换

enum SAFEMODLE
{
    no = 0,
    Caesar = 1,
    user = 2
};

class mylib
{
private:
    std::fstream f;
    char *File_Name;
    int Header_Len = 0;
    char **Table_Header;
    SAFEMODLE Safe_Modle;
    void (*DEfuncp)(char *);
    void IDGet_Time(char (&ID)[6]);
    int Encryption(char *str); // 加密
    int Decryption(char *str); // 解密

public:
    mylib(char *file_name, char *table_header, SAFEMODLE sm); // 库名,表头(key为第一个),安全级
    ~mylib();
    bool if_file_exist(char *file_name);
    void __DEBUG();
    int save(char *line);
    int delet(char *key);
    myqueue<char> find(char *sign);
    myqueue<char> find(char *sign, int point); // 从某点开始
    myqueue<char *> find_all(char *sign);
    int list();
    int list(int point); // 从某点开始
    void setDE(void (*DEfuncp)(char *));
};

mylib::mylib(char *file_name, char *table_header, SAFEMODLE sm)
{
    if (!if_file_exist(file_name)) // 不存在就创建
    {
        f.open(file_name, std::ios::app);
        f << BSEPARATOR;
        f.close();
    }
    File_Name = file_name;
    Table_Header = Input_Cut(table_header, Header_Len);
    Safe_Modle = sm;
    DEfuncp = nullptr;
}

bool mylib::if_file_exist(char *file_name)
{
    f.open(file_name);
    if (!f.good()) // 检查存在
    {
        f.close();
        return false;
    }
    f.close();
    return true;
}

void mylib::__DEBUG()
{
    // std::cout << "file_name:" << File_Name << "\nTable_Header" << Table_Header << "\nSafeMoudle" << Safe_Modle << std::endl;
    char ID[6];
    IDGet_Time(ID);
    std::cout << ID << std::endl;
}

int mylib::save(char *line)
{
    int Save_Len = 0, NowCellNum = 0;
    char **Save_Cells = Input_Cut(line, Save_Len);
    f.open(File_Name, std::ios::app);
    for (int i = 0; i < Header_Len; i++)
    {
        if (If_Str_Equ(NAMESTRS[0], Table_Header[i])) // ID
        {
            char ID[6];
            IDGet_Time(ID);
            Encryption(ID);
            f << ID << ASEPARATOR;
        }
        if (If_Str_Equ(NAMESTRS[1], Table_Header[i])) // int
        {
            if (If_Str_Int(Save_Cells[NowCellNum]))
            {
                Encryption(Save_Cells[NowCellNum]);
                f << Save_Cells[NowCellNum] << ASEPARATOR;
            }
            NowCellNum++;
        }
        if (If_Str_Equ(NAMESTRS[2], Table_Header[i])) // str
        {
            Encryption(Save_Cells[NowCellNum]);
            f << Save_Cells[NowCellNum] << ASEPARATOR;
            NowCellNum++;
        }
        if (If_Str_Equ(NAMESTRS[3], Table_Header[i])) // time
        {
            char buffer[80];
            time_t t = time(NULL);
            struct tm *tm = localtime(&t);
            strftime(buffer, 80, "%Y-%m-%d-%H:%M:%S", tm);
            Encryption(buffer);
            f << buffer << ASEPARATOR;
        }
    }
    f << BSEPARATOR;
    f.close();
    for (int i = 0; i < Save_Len; i++) // 回收内存
        delete[] Save_Cells[i];
    return 0;
}

int mylib::delet(char *key)
{
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return 1;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    Decryption(file_data);                    // 解密
    int pointK = Str_Find(file_data, key, 0); // 找到key
    if (pointK >= 0)
    {
        char line_end[3] = {ASEPARATOR, BSEPARATOR, '\0'};
        int pointE = Str_Find(file_data, line_end, pointK);
        for (int i = pointK; i <= pointE + 1; i++)
            file_data[i] = PLACEHOLDING;
    }
    else
        return -1;
    f.open(File_Name, std::ios::out); // 不能用trunk，其是unix的
    if (!f)
    {
        std::cerr << "File cannot be opened\n";
        return -1;
    }
    Encryption(file_data);
    for (int i = 0; i < file_size; i++)
    {
        if (PLACEHOLDING != file_data[i])
            f << file_data[i];
    }
    f.close();
    return 0;
}

myqueue<char> mylib::find(char *sign)
{
    myqueue<char> rene;
    rene.push('-');
    rene.push('1');
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return rene;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    Decryption(file_data);                     // 解密
    int pointK = Str_Find(file_data, sign, 0); // 找到点
    if (pointK >= 0)
    {
        char line_end[3] = {ASEPARATOR, BSEPARATOR, '\0'};
        int pointE = Str_Find(file_data, line_end, pointK), pointB = -1; // 找到结尾
        for (int i = pointK; i >= 0; i--)
        {
            if (BSEPARATOR == file_data[i])
            {
                pointB = i; // 找到开头
                break;
            }
        }
        if (pointB >= 0)
        {
            myqueue<char> restr;
            for (int i = pointB + 1; i < pointE; i++)
            {
                if (file_data[i] == ASEPARATOR)
                    restr.push(';');
                else
                    restr.push(file_data[i]);
            }
            return restr;
        }
        else
            return rene;
    }
    else
        return rene;
}

myqueue<char> mylib::find(char *sign, int point) // 从某点开始
{
    myqueue<char> rene;
    rene.push('-');
    rene.push('1');
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return rene;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    if (point >= file_size)
    {
        std::cout << "point err";
        return rene;
    }
    Decryption(file_data);                         // 解密
    int pointK = Str_Find(file_data, sign, point); // 找到点
    if (pointK >= 0)
    {
        char line_end[3] = {ASEPARATOR, BSEPARATOR, '\0'};
        int pointE = Str_Find(file_data, line_end, pointK), pointB = -1; // 找到结尾
        for (int i = pointK; i >= 0; i--)
        {
            if (BSEPARATOR == file_data[i])
            {
                pointB = i; // 找到开头
                break;
            }
        }
        if (pointB >= 0)
        {
            myqueue<char> restr;
            for (int i = pointB + 1; i < pointE; i++)
            {
                if (file_data[i] == ASEPARATOR)
                    restr.push(';');
                else
                    restr.push(file_data[i]);
            }
            return restr;
        }
        else
            return rene;
    }
    else
        return rene;
}

myqueue<char *> mylib::find_all(char *sign)
{
    char rere[3] = {'-', '1', '\0'};
    myqueue<char *> rene;
    rene.push(rere);
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return rene;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    Decryption(file_data); // 解密
    int pointK = 0;
    myqueue<char *> restrs;
    while (pointK <= file_size && pointK >= 0)
    {
        pointK = Str_Find(file_data, sign, pointK + 1); // 找到点
        if (pointK >= 0)
        {
            char line_end[3] = {ASEPARATOR, BSEPARATOR, '\0'};
            int pointE = Str_Find(file_data, line_end, pointK), pointB = -1; // 找到结尾
            for (int i = pointK; i >= 0; i--)
            {
                if (BSEPARATOR == file_data[i])
                {
                    pointB = i; // 找到开头
                    break;
                }
            }
            if (pointB >= 0)
            {
                char *restr = new char[pointE - pointB](); // 初始化空
                int jre = 0;
                for (int i = pointB + 1; i < pointE; i++)
                {
                    if (file_data[i] == ASEPARATOR)
                        restr[jre++] = ';';
                    else
                        restr[jre++] = file_data[i];
                }
                restr[jre] = '\0';
                restrs.push(restr);
            }
        }
    }
    if (restrs.len() == 0)
    {
        return rene;
    }
    return restrs;
}

int mylib::list()
{
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return -1;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    Decryption(file_data); // 解密
    for (int i = 0; i < file_size + 1; i++)
    {
        if (BSEPARATOR == file_data[i] && i != 0)
            std::cout << std::endl;
        else if (ASEPARATOR == file_data[i])
            std::cout << ";";
        else
            std::cout << file_data[i];
    }
    return 0;
}

int mylib::list(int point) // 从某点开始
{
    f.open(File_Name, std::ios::in);
    if (!f)
    {
        std::cerr << "File open err!\n";
        return -1;
    }
    f.seekg(0, std::ios::end);
    int file_size = f.tellg(); // 获取文件长度
    f.seekg(0, std::ios::beg); // 指针拉回来
    char file_data[file_size + 1];
    f.read(file_data, file_size + 1);
    f.close();
    if (point >= file_size)
    {
        std::cout << "point err";
        return -1;
    }
    Decryption(file_data); // 解密
    for (int i = point; i < file_size + 1; i++)
    {
        if (BSEPARATOR == file_data[i] && i != 0)
            std::cout << std::endl;
        else if (ASEPARATOR == file_data[i])
            std::cout << ";";
        else
            std::cout << file_data[i];
    }
    return 0;
}

void mylib::setDE(void (*DEfuncpx)(char *))
{
    DEfuncp = DEfuncpx;
}

mylib::~mylib()
{
    for (int i = 0; i < Header_Len; i++) // 回收内存
        delete[] Table_Header[i];
}

void mylib::IDGet_Time(char (&ID)[6]) // 根据时间的ID生成器
{
    std::mt19937 rng(time(NULL)); // 随机引擎
    for (int i = 0; i < 5; i++)
    {
        int tmp = rng() % 36;
        if (tmp < 10)
        {
            ID[i] = char(48 + tmp);
        }
        else
        {
            ID[i] = char(97 + tmp - 10);
        }
    }
    ID[5] = '\0';
}

int mylib::Encryption(char *str)
{
    if (Safe_Modle == no)
        return 0;
    if (Safe_Modle == Caesar)
    {
        int i = 0;
        while ('\0' != str[i])
        {
            if (str[i] != ASEPARATOR && str[i] != BSEPARATOR && str[i] != PLACEHOLDING)
                str[i] = str[i] - 3;
            i++;
        }
        return 0;
    }
    if (Safe_Modle == user)
    {
        if (DEfuncp == nullptr)
            COUT << "Encryption ERR:No encryption function input!\n";
        else
        {
            DEfuncp(str);
            return 0;
        }
    }

    return -1;
}

int mylib ::Decryption(char *str)
{
    if (Safe_Modle == no)
        return 0;
    if (Safe_Modle == Caesar)
    {
        int i = 0;
        while ('\0' != str[i])
        {
            if (str[i] != ASEPARATOR && str[i] != BSEPARATOR && str[i] != PLACEHOLDING)
                str[i] = str[i] + 3;
            i++;
        }
        return 0;
    }
    if (Safe_Modle == user)
    {
        if (DEfuncp == nullptr)
            COUT << "Dncryption ERR:No dncryption function input!\n";
        else
        {
            DEfuncp(str);
            return 0;
        }
    }
    return -1;
}

/*void a(char *str)
{
    int i = 0;
    while ('\0' != str[i])
    {
        if (str[i] != ASEPARATOR && str[i] != BSEPARATOR && str[i] != PLACEHOLDING)
            str[i] = str[i] - 3;
        i++;
    }
}

int main()
{
    char fil[] = "testlib", tab[] = "ID;int;str;str;time", line[] = "12;3lllllllll4;5ko-", tmp[] = "ko";
    mylib liba(fil, tab, user);
    liba.setDE(&a);
    liba.save(line);
    // liba.save(line);
    return 0;
}*/