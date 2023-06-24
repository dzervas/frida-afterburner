#include "my.hpp"

int main() {
	std::string str1 = ret_string();
	std::basic_string<char> str2 = ret_bstring();
	std::wstring str3 = ret_wstring();
	std::basic_string<wchar_t> str4 = ret_bwstring();
	char str5[5] = "wow";

	std::cout << str1 << " " << str2 << " " << str5 << std::endl;
	std::wcout << str3 << L" " << str4 << std::endl;

	return 0;
}
