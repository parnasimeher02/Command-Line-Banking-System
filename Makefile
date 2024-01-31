JCC = javac

JFLAGS = -g

default: BankServer.class UserClient.class RSAEncryptionWithAES.class
	
BankServer.class: BankServer.java
	$(JCC) $(JFLAGS) BankServer.java
	
UserClient.class: UserClient.java
	$(JCC) $(JFLAGS) UserClient.java
	
RSAEncryptionWithAES.class: RSAEncryptionWithAES.java
	$(JCC) $(JFLAGS) RSAEncryptionWithAES.java
	
clean: 
	$(RM) *.class