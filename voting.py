n1=input("enter name of 1")
n2=input("enter name of 2")

c1=0
c2=0

Vote_id=[1,2,3,4,5]

while True:
	if Vote_id==[]:
		print("Voting over")
		if c1 > c2:
			print(n1,'has won with',c1, 'votes')
			break
		elif c2 > c1:
			print(n2,'has won with',c2, 'votes')
			break
		
	else:
		voter=int(input("Voter id:"))
		if voter in Vote_id:
			Vote_id.remove(voter)
			vote=int(input("Enter 1 or 2:"))
			if vote == 1:
				c1+=1
				print('vote casted for 1')
			elif vote == 2:
				c2+=1
				print('vote casted for 2')
		else:
			print("you have voted or you are not a voter")
