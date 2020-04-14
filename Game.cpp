#include <iostream>

using namespace std;

class Game{
  public:

    static const size_t WIDTH = 7;
    static const size_t HEIGHT = 6;

    //allocates a 2 dimentional array and initializes it with ' '
    char** createBoard(){
      char** ret = new char*[HEIGHT];

      for (size_t i = 0; i < HEIGHT; i++) {
        ret[i] = new char[WIDTH];

        for(size_t j = 0; j < WIDTH; j++){
          ret[i][j] = ' ';
        }
      }
      return ret;
    }

    // deallocates the two dimentional array
    void deleteBoard(char** board){

      for (size_t i = 0; i < HEIGHT; i++) {
        delete[] board[i];
      }
      delete[] board;
    }

    // prints the board with rows in reverse order
    /*     [5][0] [5][1]
           [4][0] [4][1]
           [3][0] [3][1]
           [2][0] [2][1]
           [1][0] [1][1]
           [0][0] [0][1] etc...
    board=
    */
    void printBoard(char** board){
      cout<<endl;

      for (int i = HEIGHT-1; i >=0 ; i--) {
        cout<<"|"; // left border

        for (size_t j = 0; j < WIDTH; j++) {
          cout<<" "<<board[i][j]<<" ";
        }

        cout<<"|"<<endl; // right border
      }
      cout<<"  -  -  -  -  -  -  -  "<<endl<<"  0  1  2  3  4  5  6"<<endl;
    }


    bool insertPiece(char** board, char piece, size_t column){

      // is it correct? PS: it cannot be negative
      if(column >= WIDTH){cout<<"Posizione non valida"<<endl; return false;}

      // starting from the bottom row, I look for a free spot in the selected column
      for (size_t i = 0; i < HEIGHT; i++) {

        if(board[i][column] == ' '){
          board[i][column] = piece;
          return true;
        }
      }
      // no free spot available
      cout<<"Colonna Piena"<<endl;
       return false;
    }


    // returns true if the player with "piece" has won
    // obviusly only the player who made the latest move can win
    bool checkWin(char** board, char piece){


      for (size_t i = 0; i < HEIGHT; i++) {
        for (size_t j = 0; j < WIDTH; j++) {
          if(board[i][j] != piece) // useless spot for our porpuse
            continue;

          /* if I arrive here (i,j) needs to be investigated
             going through the board from bottom to top and from left to right
             there are only 4 winning scenarios:
             3 other pieces on the right, or above, or right diagonal  or left diagonal
          */

          if(
             j + 3 < WIDTH && // are there 3 other spots on my right?
             board[i][j+1] == piece &&
             board[i][j+2] == piece &&
             board[i][j+3] == piece
            )
            return true;

          if(i + 3 < HEIGHT){ // for all other cases I have to go up 3 spots

            // check above
            if(
               board[i+1][j] == piece &&
               board[i+2][j] == piece &&
               board[i+3][j] == piece
              )
              return true;

            //check right diagonal
            if(
               j + 3 < WIDTH &&
               board[i+1][j+1] == piece &&
               board[i+2][j+2] == piece &&
               board[i+3][j+3] == piece
            )
            return true;

            //check left diagonal
            if(
               j - 3 >= 0 &&
               board[i+1][j-1] == piece &&
               board[i+2][j-2] == piece &&
               board[i+3][j-3] == piece
            )
            return true;
          }
        }
      }

      // no winning configuration has been found
      return false;
    }

    // returns true if no other moves can be made
    bool isBoardFull(char** board){

      for (size_t i = 0; i < HEIGHT; i++) {
        for (size_t j = 0; j < WIDTH; j++) {
          if(board[i][j] == ' ')
            return false;
        }
      }
      // The game is over
      return true;
    }

};


// main di prova con 2 giocatori locali
int main(){

  Game g;
  char** board = g.createBoard();
  size_t column;

  g.printBoard(board);

  while(true){
    // giocatore 1
    cout<<"(Giocatore 1) Inserisci colonna: ";
    cin>>column;

    g.insertPiece(board, 'X', column);

    g.printBoard(board);

    if(g.checkWin(board, 'X')){
      cout<<"Giocatore 1 ha vinto!!!"<<endl;
      break;
    }
    if(g.isBoardFull(board)){
      cout<<"Pareggio"<<endl;
      break;
    }

    // giocatore 2
    cout<<"(Giocatore 2) Inserisci colonna: ";
    cin>>column;

    g.insertPiece(board, 'O', column);

    g.printBoard(board);

    if(g.checkWin(board, 'O')){
      cout<<"Giocatore 2 ha vinto!!!"<<endl;
      break;
    }
    if(g.isBoardFull(board)){
      cout<<"Pareggio"<<endl;
      break;
    }

  }

  cout<<"Chiusura gioco..."<<endl;

  g.deleteBoard(board);

}
