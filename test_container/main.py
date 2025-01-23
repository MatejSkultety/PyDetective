import pandas as pd

def main():
    num = int(input("Enter a number: "))
    while num != 0:
        df = pd.DataFrame({'A': [i for i in range(num)], 'B': [1] * num})
        print(df)
        append_to_file(num, 'data.txt')
        num = int(input("Enter a number: "))


def append_to_file(number, file_path):
    with open(file_path, 'a') as file:
        file.write(f"{number}\n")
            

if __name__ == "__main__":
    main()
  