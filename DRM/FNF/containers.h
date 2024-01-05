#pragma once


#include <algorithm> 

template<class T>
struct TArray
{
	friend struct FString;

public:
	T* Data;
	int32_t Count;
	int32_t Max;

	inline TArray()
	{
		Data = nullptr;
		Count = Max = 0;
	};

	inline int Num() const
	{
		return Count;
	};

	inline T& operator[](int i)
	{
		return Data[i];
	};

	inline const T& operator[](int i) const
	{
		return Data[i];
	};

	inline bool IsValidIndex(int i) const
	{
		return i < Num();
	}


	inline void Add(T InputData)
	{
		Data = (T*)realloc(Data, sizeof(T) * (Count + 1));
		Data[Count++] = InputData;
		Max = Count;
	};

	inline void Remove(int32_t Index)
	{
		TArray<T> NewArray;
		for (size_t i = 0; i < this->Count; ++i)
		{
			if (i == Index)
				continue;

			NewArray.Add(this->operator[](i));
		}
		this->Data = (T*)realloc(NewArray.Data, sizeof(T) * (NewArray.Count));
		this->Count = NewArray.Count;
		this->Max = NewArray.Count;
	}



	inline void Remove(T InData)
	{
		TArray<T> NewArray;
		for (size_t i = 0; i < this->Count; ++i)
		{
			if (this->operator[](i) != InData)
			{
				NewArray.Add(this->operator[](i));
			}
		}
		this = NewArray;
	}

	inline bool IsValid()
	{
		return Data != nullptr;
	}

};

