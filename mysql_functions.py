import mysql.connector

class Connection():

    def __init__(self, host='localhost', user='root', password='', database=''):
        try:
            if database != '':
                self.conn = mysql.connector.connect(
                    host = host,
                    user = user,
                    password = password,
                    database = database
                )
            else:
                self.conn = mysql.connector.connect(
                    host = host,
                    user = user,
                    password = password,
                )

        except:
            self.conn = False

        self.mycursor =  False if not self.conn else self.conn.cursor()
        self.syntaxError = 'You have an error in your SQL syntax'

    def CheckConnection(self):
        return self.conn


    def deleteQuery(self, query):
        try:
            self.mycursor.execute(query)
            self.conn.commit()
        except:
            raise Exception(self.syntaxError)


    def query(self, query, sql=''):
        try:
            if query.find('INSERT') == 0:

                if sql != '':
                    self.mycursor.execute(query, sql)
                    self.conn.commit()
                    return self.mycursor.rowcount, 'record inserted'

                self.mycursor.execute(query)
                self.conn.commit()
                return self.mycursor.rowcount, 'record inserted'
            elif query.find('CREATE') == 0:
                self.mycursor.execute(query)
                return 0
            else:
                result = []
                self.mycursor.execute(query)
                for i in self.mycursor:
                    result.append(i)
                return result
        except:
            raise Exception(self.syntaxError)


    def queryMultiple(self, query, values):
        try:
            self.mycursor.executemany(query, values)
            self.conn.commit()
            return 0
        except:
            raise Exception(self.syntaxError)
