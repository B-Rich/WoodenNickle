total_amnt = 0

with open("private_coin_storage.txt", "r") as myfile:
    for line in myfile.readlines():
        total_amnt += int(line.split('\t')[0])

print('Total coins: {}'.format(total_amnt))
