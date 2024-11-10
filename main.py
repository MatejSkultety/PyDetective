import pandas as pd

def main():
    num = int(input("Enter a number: "))
    while num != 0:
        df = pd.DataFrame({'A': [i for i in range(num)], 'B': [1] * num})
        print(df)
        num = int(input("Enter a number: "))

if __name__ == "__main__":
    main()