#pragma once

#include <vector>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <iostream>



TArray<char> Conv_StringToCharArray(std::string InString) {
	TArray<char> Temp;
	for (int i = 0; i < InString.size(); i++)
		Temp.Add(InString[i]);
	return Temp;
}


std::string ExtractObjectFromBuff(std::string InBuff) {
	size_t startPos = InBuff.find("{");
	if (startPos != std::string::npos) {
		size_t endPos = InBuff.rfind("}");
		if (endPos != std::string::npos) {
			return InBuff.substr(startPos, endPos - startPos + 1);
		}
		else {
			return "";
		}
	}
	else {
		return "";
	}
}

std::vector<unsigned char> decodeBase64(const std::string& encoded) {
	using namespace boost::archive::iterators;
	using It = transform_width<binary_from_base64<std::string::const_iterator>, 8, 6>;

	std::vector<unsigned char> decoded;
	try {
		size_t numPads = count(encoded.begin(), encoded.end(), '=');
		std::string base64Padded(encoded);
		base64Padded.erase(base64Padded.size() - numPads);

		decoded.assign(It(base64Padded.begin()), It(base64Padded.end()));
	}
	catch (const std::exception& e) {
		std::cerr << "Error decoding Base64: " << e.what() << std::endl;
	}
	return decoded;
}