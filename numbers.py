# Python program to
# compute sum of digits in 
# number.
   
# Function to get sum of digits 
def getSum(n):
    
    sum = 0
    for digit in str(n): 
        for i in range(1,30):
            sum += int(digit)     
    return sum
   
n = 5879
print(getSum(n))