#!/bin/python3
import argparse
import logging
import sqlite3
from base64 import urlsafe_b64encode
import hashlib as hashlib
from cryptography.fernet import Fernet


class Arguments:
  """ Automated argument handling framework for bigger projects.

      Accepts a single required argument, ArgumentDictionary, which
  is a nested dictionary structured with keys for flag options, help text,
  a classification type, and the correct action to apply.

      Example:

        ArgumentDict = {
          0: {
            "options": ["-short", "--long"],
            "help": 'A short description of what this argument does.',
            "type": type(value_to_be_collected_by_argument),
            "action": str("ArgParse action string to be taken.")
          }
        }
  """
  def __init__(self, ArgumentDict: dict):
    self.parser = argparse.ArgumentParser()

    for argument in ArgumentDict.keys():
      argument = ArgumentDict[argument]
      self.parser.add_argument(
                                argument['options'][0],
                                argument['options'][1],
                                help=str(argument['help']),
                                type=argument['class'],
                                action=str(argument['action']) )

    self.args = self.parser.parse_args()





class Logger:
  """ Logging setup and associated functionality. """

  def __init__( self,
                logfile="./.log",
                loglevel=logging.INFO ):
    logging.basicConfig(filename=logfile, level=loglevel)


  def INFO(msg: str):
    return logging.info(msg)


  def DEBUG(msg: str):
    return logging.debug(msg)


  def ErrorHandling(error):
    return logging.exception("An error was caught:\n{error}\n")





class Security:

  class Cryptography:
    """ A collection of tools specifically dealing with the security
    of certain given credentials.

    One-Way SHA-256 hashes are implemented through self.SHA256()
    Two-Way Fernet encryption is implemented through self.Encryption()
      -- Custom keys are created with self.BuildKey(), which allows
         for the use of an 'imaginary' encr
    """
    def __init__(self): pass

    def SHA256(self, secret: str):
      """ Create a SHA-256 hash of whatever value is given. """
      return hashlib.sha256(secret.encode()).hexdigest()


    def BuildKey(self, username: str, password: str):
      """ Create a two-way encryption key using the first 32
      digits of the hash of a username and password strings.

          The results are then encoded in urlsafe-base64 bytes
      and returned to thre caller. """
      basecode = self.SHA256(str(username + password))[:32]
      key = urlsafe_b64encode(basecode.encode())
      return key


    def Encryption(self, phrase: bytes, target: str):
      intelligence = Fernet(phrase)
      return intelligence.encrypt(bytes(target, 'utf-8'))
  

    def Decryption(self, phrase: bytes, target: str):
      intelligence = Fernet(phrase)
      return intelligence.decrypt(target)





class Database:
  """ A collection of functions for interacting with the
  applications underlying database.  Functionality includes
  a base layer of constants to facilitate work, the ability
  to determine whether or not to add a column to a table,
  """


  def __init__( self,
                database="./sqlite3-database.db",
                *tables: list,
                **columns: dict                   ):
    """ Sets up a couple of variables for use by the other
    functions:

    db         - Database file.

    crypto     - Encryption functions.

    connection - Database connection.
                 Required for safely closing a db
                 connection.

    cursor     - Connection cursor.
                 Used for all SQLite3 queries.
                 
        We can also initialize our database with any
    required tables and all of their associated columns
    by way of the optional *tables and **columns arguments.

        These arguments are given as a list and dictionary,
    respectively; where the columns dictionaries are named
    after themselves, with a "table," and "type" key whose
    values are the columns associated table and their data-
    types
    """

    try:""" First we attempt to set up all the required
    connections to our database, then we check the master
    record for a table matching our requirements.
    
        Once we create any tables we may need, then we
    iterate through the list of columns and apply them
    to their respective tables. """

      # Sqlite3 Boilerplate Code.
      self.db = database
      self.connection = sqlite3.connect(self.db)
      self.cursor = self.connection.cursor()    

      # Check for table existence.
      for table in tables:
        table = str(table.lower().replace(" ", "-"))
        self.cursor.execute(
          f"SELECT name FROM sqlite_master "
          f"WHERE type='table' AND name=?;",
          (table,)
        )

        # Do nothing if the table already exists. 
        if len(
          self.cursor\
              .fetchall()
        ) > 0: pass

        else:# Create the table if it doesn't.
          self.cursor\
              .execute(
                "CREATE TABLE IF NOT EXISTS ?()",
                (table,)
              )

          # Save any changes.
          self.connection.commit()

      # Populate the table with its associated column headers.
      for column in columns:

        # Format the column name, according to standard.
        column = self.TableHeader_PacketParser(column)

        column_table = column[0]
        column_name = column[1]
        column_type = column[2]
          
        # Add the column to the table.
        self.cursor\
            .execute(
              "ALTER TABLE ? ADD COLUMN ? ?;",
              ( column_table,
                column_name,
                column_type
                             )                 )

        # Save your work!
        self.connection.commit()

    except: break#ErrorHandling(error)


  def TableHeader_PacketParser( self,
                                HeaderPacket: dict ):
    return [
      str( HeaderPacket["table"]\
                      .lower()\
                      .replace(" ","-") ),

      str( HeaderPacket["name"]\
                      .lower()\
                      .replace(" ","-") ),

      str( HeaderPacket["type"]\
                       .upper()  )
    ]


  def Check_Column_Existence( self,
                              table,
                              header ):
    """ Check a given table for the existence of said header within it. """

    # Format the arguments according to standards.
    table = table\
            .lower()\
            .replace(" ","-")

    header = header\
             .lower()\
             .replace(" ","-")

    # List every column header in the credentials table.
    columns = self.cursor\
                  .execute(
                            "PRAGMA table_info(?);",
                            (table,)
                          )\
                  .fetchall()[0]

    # Check whether the given header matches those listed.
    for column in columns:
      if (column == header):
        return True

    
  def Add_Column_Header( self,
                         columns: dict ):
    """ Add a series of columns to a table associated
    with them, in the same way that the init process
    runs."""
    for column in columns:
      column = self.TableHeader_PacketParser(column)

      column_table = column[0]
      column_name = column[1]
      column_type = column[2]

      self.cursor.execute(
                          "ALTER TABLE ? ADD COLUMN ? ?;",
                          ( column_table,
                            column_name,
                            column_type )                  )
    # Kakashi Sensei says: Always save your work.
    return self.cursor.commit()


  def Credential_Lookup( self,
                         credential: str,
                         table: str,
                         comparator: str,
                         input: str,
                         validate: False,
                         value=""         ):
    """ Searches a $table's $credential column for
    matches against a $comparator column by any given
    $input.

        If the _results of this query match a specific
    $value, then return True. """

    self.cursor.execute(
      "SELECT ? FROM ? WHERE ?=?;",
      (credential, table, comparator, input)
    )

    _results = self.cursor.fetchall[0]

    if len(_results) > 0:

      if validate == True:
        if str(_results[0]) == str(value):
          return True

      else: return _results[0]