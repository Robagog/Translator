#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string.h>
using namespace std;

const int idents_limit = 1024; // max amount of identificators in program
const int poliz_array_size = 1024; // size of POLIZ, lextype and Arg stacks
const int cycles_depth = 32; // max cycles recursion depth
const int breaks_depth = 32; // max amount of breaks in cycle

const int scanner_debug = 0;
const int parser_debug = 0;
const int poliz_debug = 0;
const int execute_debug = 0;
const int write_bool_as_int = 0;

enum type_of_lex
{
	LEX_NULL = 0,
	LEX_AND,
	LEX_BOOL,
	LEX_BREAK,
	LEX_GOTO,
	LEX_ELSE,
	LEX_IF,
	LEX_FALSE,
	LEX_FOR,
	LEX_INT,
	LEX_NOT,
	LEX_OR,
	LEX_PROGRAM,
	LEX_READ,
	LEX_TRUE,
	LEX_STRING,
	LEX_WHILE,
	LEX_WRITE,

	LEX_SEMICOLON,
	LEX_COMMA,
	LEX_COLON,
	LEX_ASSIGN,
	LEX_LPAREN,
	LEX_RPAREN,
	LEX_EQ,
	LEX_LS,
	LEX_GT,
	LEX_PLUS,
	LEX_MINUS,
	LEX_TIMES,
	LEX_SLASH,
	LEX_LE,
	LEX_NE,
	LEX_GE,
	LEX_PRCNT,
	LEX_BEGIN,
	LEX_END, // 38

	LEX_NUM,
	LEX_STR,
	LEX_ID,
	LEX_LABEL,
	LEX_UNARY,
	LEX_FIN,

	POLIZ_LABEL,
	POLIZ_ADDRESS,
	POLIZ_GO,
	POLIZ_FGO,
};

static const char *lexems[] =
{
	[LEX_NULL] = "null",
	[LEX_AND] = "and",
	[LEX_BOOL] = "bool",
	[LEX_BREAK] = "break",
	[LEX_GOTO] = "goto",
	[LEX_ELSE] = "else",
	[LEX_IF] = "if",
	[LEX_FALSE] = "false",
	[LEX_FOR] = "for",
	[LEX_INT] = "int",
	[LEX_NOT] = "not",
	[LEX_OR] = "or",
	[LEX_PROGRAM] = "program",
	[LEX_READ] = "read",
	[LEX_TRUE] = "true",
	[LEX_STRING] = "string",
	[LEX_WHILE] = "while",
	[LEX_WRITE] = "write",
	[LEX_SEMICOLON] = ";",
	[LEX_COMMA] = ",",
	[LEX_COLON] = ":",
	[LEX_ASSIGN] = "=",
	[LEX_LPAREN] = "(",
	[LEX_RPAREN] = ")",
	[LEX_EQ] = "==",
	[LEX_LS] = "<",
	[LEX_GT] = ">",
	[LEX_PLUS] = "+",
	[LEX_MINUS] = "-",
	[LEX_TIMES] = "*",
	[LEX_SLASH] = "/",
	[LEX_LE] = "<=",
	[LEX_NE] = "!=",
	[LEX_GE] = ">=",
	[LEX_PRCNT] = "%",
	[LEX_BEGIN] = "{",
	[LEX_END] = "}",

	[LEX_NUM] = "num",
	[LEX_STR] = "str",
	[LEX_ID] = "ident",
	[LEX_LABEL] = "label",
	[LEX_UNARY] = "@",
	[LEX_FIN] = "final",

	[POLIZ_LABEL] = "pz_labl",
	[POLIZ_ADDRESS] = "pz_addr",
	[POLIZ_GO] = "pz_go",
	[POLIZ_FGO] = "pz_fgo",
};

class Arg {
public:
	type_of_lex type;
	int val;
	std::string sval;

	Arg() { type = LEX_INT; val = 0; sval = ""; }
	Arg(int a) { type = LEX_INT; val = a; sval = ""; }
	Arg(bool b) { type = LEX_BOOL; val = b ? 1 : 0; sval = ""; }

	Arg(std::string s) {
		type = LEX_STRING;
		val = 0;
		sval = s;
	}
};

class Lex
{
	type_of_lex t_lex;
	int v_lex;
	std::string s_lex;

public:
	Lex (type_of_lex t = LEX_NULL, int v = 0)
	{
		t_lex = t; v_lex = v; s_lex = "";
	}

	Lex (type_of_lex t, char *s)
	{
		t_lex = t; v_lex = 0; s_lex = s;
	}

	type_of_lex get_type() {
		return t_lex;
	}

	int get_value() {
		return v_lex;
	}

	std::string get_string() {
		return s_lex;
	}

	Arg get_arg() {
		if (t_lex == LEX_STR)
			return Arg(s_lex);
		else if (t_lex == LEX_NUM)
			return Arg(v_lex);
		else if (t_lex == LEX_TRUE || t_lex == LEX_FALSE)
			return Arg(!!v_lex);
		return Arg(v_lex);
	}

	friend ostream& operator << ( ostream &s, Lex l ) {
		s << "[" << lexems[l.t_lex] << "]: " << l.v_lex << (l.s_lex.length() > 0 ? ", "+l.s_lex : "") << " ;";
		return s;
	}
};

#define throw_lex(lex) throw lex;

class Ident
{
	char *name;
	bool declare;
	type_of_lex type;
	bool assign;
	Arg arg;

public:
	Ident() : arg()
	{
		declare = false;
		assign = false;
	}

	char *get_name() {
		return name;
	}

	void set_name(const char *n) {
		name = new char[strlen(n) + 1];
		strcpy(name, n);
	}

	bool get_declare() {
		return declare;
	}

	void set_declare() {
		declare = true;
	}

	type_of_lex get_type() {
		return type;
	}

	void set_type(type_of_lex t) {
		type = t;
	}

	bool get_assign() {
		return assign;
	}

	void set_assign() {
		assign = true;
	}

	int get_value() {
		return arg.val;
	}

	Arg get_arg() {
		return arg;
	}

	void set_value(bool b) {
		arg.type = LEX_BOOL;
		arg.val = b ? 1 : 0;
	}

	void set_value(int v) {
		arg.type = LEX_INT;
		arg.val = v;
	}

	void set_value(std::string s) {
		arg.type = LEX_STRING;
		arg.sval = s;
	}
};

class tabl_ident
{
	Ident *p;
	int size;
	int top;

public:
	tabl_ident(int max_size) {
		p = new Ident[size=max_size];
		top = 1;
	}
	~tabl_ident() {
		delete []p;
	}

	Ident& operator[] (int k) {
		return p[k];
	}

	int add_ident(const char *buf);
};

int tabl_ident::add_ident(const char *buf)
{
	for (int j = 1; j < top; ++j)
		if (!strcmp(buf, p[j].get_name()))
			return j;
	p[top++].set_name(buf);
	return top - 1;
}

class Scanner
{
	enum state { H, IDENT, NUMB, TRYCOM, COM, STR, ALE, DELIM, NEQ };
	static const char *TW[];
	static type_of_lex words[];
	static const char *TD[];
	static type_of_lex dlms[];
	state cur_state;
	FILE *fp;
	char c;
	char buf[1024];
	int buf_top;

	void clear_buf() {
		memset(buf, '\0', 1024);
		buf_top = 0;
	}

	void add2buf() {
		if (buf_top < 1024)
			buf[buf_top++] = c;
		else
			throw "Scanner::buf[] buffer overflow";
	}

	int look(const char *buf, const char **list) {
		int i = 0;

		while (list[i]) {
			if (!strcmp(buf, list[i]))
				return i;
			++i;
		}
		return 0;
	}

	void next_char() {
		c = fgetc(fp);
		if (scanner_debug)
			cout << "lex_state: "<< cur_state << ", char: " << c << endl;
	}

public:
	Lex get_lex();

	Scanner(const char * program) {
		fp = fopen(program, "r");
		cur_state = H;
		clear_buf();
		next_char();
	}
};

const char * Scanner::TW[] =
{
	"",
	"and",
	"boolean",
	"break",
	"goto",
	"else",
	"if",
	"false",
	"for",
	"int",
	"not",
	"or",
	"program",
	"read",
	"true",
	"string",
	"while",
	"write",
	NULL
};

type_of_lex Scanner::words[] =
{
	LEX_NULL,
	LEX_AND,
	LEX_BOOL,
	LEX_BREAK,
	LEX_GOTO,
	LEX_ELSE,
	LEX_IF,
	LEX_FALSE,
	LEX_FOR,
	LEX_INT,
	LEX_NOT,
	LEX_OR,
	LEX_PROGRAM,
	LEX_READ,
	LEX_TRUE,
	LEX_STRING,
	LEX_WHILE,
	LEX_WRITE,
	LEX_NULL
};

const char * Scanner::TD[] =
{
	"", // 1
	";",
	",",
	":",
	"=",
	"(",
	")",
	"==",
	"<",
	">",
	"+",
	"-",
	"*",
	"/",
	"<=",
	"!=",
	">=",
	"%",
	"{",
	"}",
	NULL
};

type_of_lex Scanner::dlms[] =
{
	LEX_NULL,
	LEX_SEMICOLON,
	LEX_COMMA,
	LEX_COLON,
	LEX_ASSIGN,
	LEX_LPAREN,
	LEX_RPAREN,
	LEX_EQ,
	LEX_LS,
	LEX_GT,
	LEX_PLUS,
	LEX_MINUS,
	LEX_TIMES,
	LEX_SLASH,
	LEX_LE,
	LEX_NE,
	LEX_GE,
	LEX_PRCNT,
	LEX_BEGIN,
	LEX_END,
	LEX_NULL
};

tabl_ident TID(idents_limit);

Lex Scanner::get_lex()
{
	int d, j;
	cur_state = H;

	do {
		switch(cur_state) {
		case H:
			if (c ==' ' || c =='\n' || c=='\r' || c =='\t') {
				next_char();
			} else if (isalpha(c)) {
				clear_buf();
				add2buf();
				next_char();
				cur_state = IDENT;
			} else if (isdigit(c)) {
				d = c - '0';
				next_char();
				cur_state = NUMB;
			} else if (c == '\"') {
				clear_buf();
				next_char();
				cur_state = STR;
			} else if (c == '/') {
				clear_buf();
				add2buf();
				next_char();
				cur_state = TRYCOM;
			} else if (c== '=' || c== '<' || c== '>') {
				clear_buf();
				add2buf();
				next_char();
				cur_state = ALE;
			} else if (c == '!') {
				clear_buf();
				add2buf();
				next_char();
				cur_state = NEQ;
			} else if (c == EOF) {
				return Lex(LEX_FIN);
			} else {
				cur_state = DELIM;
			}
			break;
		case IDENT:
			if (isalpha(c) || isdigit(c)) {
				add2buf();
				next_char();
			} else if (c == ':') {
				next_char();
				j = TID.add_ident(buf);
				return Lex(LEX_LABEL, j);
			} else {
				if (j = look(buf, TW)) {
					return Lex(words[j], j);
				} else {
					j = TID.add_ident(buf);
					return Lex(LEX_ID, j);
				}
			}
			break;
		case NUMB:
			if (isdigit(c)) {
				d = d * 10 + (c - '0');
				next_char();
			} else {
				return Lex(LEX_NUM, d);
			}
			break;
		case STR:
			if (c == '\"') { // end
				next_char();
				cur_state = H;
				return Lex(LEX_STR, buf);
			} else {
				add2buf();
				next_char();
			}
			break;
		case TRYCOM:
			if (c == '*') {
				next_char();
				cur_state = COM;
			} else {
				j = look(buf, TD);
				return Lex(dlms[j], j);
			}
		case COM:
			if (c == '*') {
				next_char();
				if (c == '/')
					cur_state = H;
			}
			next_char();
			break;
		case ALE:
			if (c == '=') {
				add2buf();
				next_char();
				j = look(buf, TD);
				return Lex(dlms[j], j);
			} else {
				j = look(buf, TD);
				return Lex(dlms[j], j);
			}
			break;
		case NEQ:
			if (c == '=') {
				add2buf();
				next_char();
				j = look(buf, TD);
				return Lex(LEX_NE, j);
			} else {
				throw '!';
			}
			break;
		case DELIM:
			clear_buf();
			add2buf();
			if (j = look(buf, TD)) {
				next_char();
				return Lex(dlms[j], j);
			} else
				throw c;
			break;
		} // end switch
	} while (true);
}

class Poliz
{
	Lex *p;
	int size;
	int rest;

public:
	Poliz (int max_size)
	{
		p = new Lex[size = max_size];
		rest = 0;
	};

	~Poliz()
	{
		delete []p;
	};

	void add_lex(Lex l)
	{
		p[rest] = l;
		++rest;
	};

	void add_lex(Lex l, int place)
	{
		p[place] = l;
	};

	void blank()
	{
		++rest;
	};

	int get_rest()
	{
		return rest;
	};

	Lex& operator[] (int index)
	{
		if (index > size)
			throw "POLIZ: out of array";
		else if (index > rest)
			throw "POLIZ: indefinite element of array";
		else
			return p[index];
	};

	void print()
	{
		for (int i = 0; i < rest; ++i)
			cout << i << "-> " << p[i] << endl;
	};
};

template <class T, int max_size >
class Stack
{
	T s[max_size];
	int top;

public:
	Stack()
	{
		top = 0;
	}

	void reset() { top = 0; }
	void push(T i);
	T pop();
	bool is_empty() { return top == 0; }
	bool is_full() { return top == max_size; }
};

template <class T, int max_size >
void Stack <T, max_size >::push(T i)
{
	if (!is_full()) {
		s[top] = i;
		++top;
	} else
		throw "Stack_is_full";
}

template <class T, int max_size >
T Stack <T, max_size >::pop()
{
	if (!is_empty()) {
		--top;
		return s[top];
	} else
		throw "Stack_is_empty";
}

class Cycle
{
	Stack < int, breaks_depth > brk;

public:
	Cycle() {}

	void add_break(int addr) {
		brk.push(addr);
	}

	int get_break() {
		return brk.is_empty() ? 0 : brk.pop();
	}
};

class Parser
{
	Lex curr_lex;
	type_of_lex c_type;
	int c_val;
	std::string c_str;

	Scanner scan;

	Stack < type_of_lex, poliz_array_size > st_lex;
	Stack < Cycle, cycles_depth > cycles;

	void P();
	void D();
	void B();
	int  S();
	void E();
	void E1();
	void E11();
	void E12();
	void T();
	void F();

	void declare(type_of_lex type);
	void check_id();
	void check_op();
	void check_not();
	void check_unary();
	void eq_type();
	void eq_bool();
	void check_id_in_read();
	void check_label();
	int  save_label(int addr);

	void next_lex()
	{
		curr_lex = scan.get_lex();
		c_type = curr_lex.get_type();
		c_val = curr_lex.get_value();
		c_str = curr_lex.get_string();
		if (parser_debug)
			cout << "lex: " << curr_lex << endl;
	}

public:
	Poliz prog;

	Parser(const char *program) : scan(program), prog(poliz_array_size) { }

	void analyze();
};

void Parser::analyze()
{
	next_lex();
	P();
	if (poliz_debug) {
		prog.print();
		cout << endl << "OK!" << endl;
	}
}

void Parser::check_label()
{
	if (TID[c_val].get_declare())
		throw "Label exists already";
	else
		TID[c_val].set_declare();
}

int Parser::save_label(int addr)
{
	int ret = 0;

	if (TID[c_val].get_assign()) {
		ret = TID[c_val].get_value();
	} else {
		TID[c_val].set_assign();
		TID[c_val].set_value(addr);
	}
	return ret;
}

void Parser::declare(type_of_lex type)
{
	if (TID[c_val].get_declare())
		throw "declared twice";
	else {
		TID[c_val].set_declare();
		TID[c_val].set_type(type);
		st_lex.push(TID[c_val].get_type());
	}
}

void Parser::check_id()
{
	if (TID[c_val].get_declare())
		st_lex.push(TID[c_val].get_type());
	else
		throw "not declared";
}

void Parser::check_op()
{
	type_of_lex t1, t2, op, t, res;

	t2 = st_lex.pop();
	op = st_lex.pop();
	t1 = st_lex.pop();

	//cout << "check op: " << t1 << op << t2;

	if (t1 != t2)
		throw "Operation on different types";
	switch(t1) {
	case LEX_INT:
		if (op == LEX_PLUS || op == LEX_MINUS || op == LEX_TIMES ||
		    op == LEX_SLASH|| op == LEX_PRCNT)
			res = LEX_INT;
		else if (op == LEX_EQ || op == LEX_LS || op == LEX_GT ||
			 op == LEX_NE || op == LEX_LE || op == LEX_GE)
			res = LEX_BOOL;
		else
			throw "wrong operation for int type";
		break;
	case LEX_STRING:
		if (op == LEX_PLUS)
			res = LEX_STRING;
		else if (op == LEX_EQ || op == LEX_LS || op == LEX_GT || op == LEX_NE)
			res = LEX_BOOL;
		else
			throw "wrong operation for string type";
		break;
	case LEX_BOOL:
		if (op == LEX_OR || op == LEX_AND || op == LEX_NE || op == LEX_EQ)
			res = LEX_BOOL;
		else
			throw "wrong operation for bool type";
		break;
	}
	st_lex.push(res);
	prog.add_lex(Lex(op));
}

void Parser::check_not()
{
	if (st_lex.pop() != LEX_BOOL)
		throw "wrong type is in not";

	st_lex.push(LEX_BOOL);
	prog.add_lex(Lex(LEX_NOT));
}

void Parser::check_unary()
{
	if (st_lex.pop() != LEX_INT)
		throw "wrong type for unary";

	st_lex.push(LEX_INT);
	prog.add_lex(Lex(LEX_UNARY));
}

void Parser::eq_type()
{
	if (st_lex.pop() != st_lex.pop())
		throw "wrong types are in '='";
}

void Parser::eq_bool()
{
	if (st_lex.pop() != LEX_BOOL)
		throw "expression is not boolean";
}

void Parser::check_id_in_read()
{
	if (!TID[c_val].get_declare())
		throw "not declared";
}

void Parser::P()
{
	if (c_type == LEX_PROGRAM)
		next_lex();
	else
		throw_lex(curr_lex);
	// empty op to handle goto 0
	prog.blank();
	B();
	if (c_type != LEX_FIN)
		throw_lex(curr_lex);
}

void Parser::D()
{
	if (c_type == LEX_INT || c_type == LEX_STRING || c_type == LEX_BOOL) {
		type_of_lex curr_type = c_type;

		do {
			next_lex();
			if (c_type != LEX_ID)
				throw_lex(curr_lex);

			declare(curr_type);

			prog.add_lex(Lex(POLIZ_ADDRESS, c_val));

			next_lex();
			if (c_type == LEX_ASSIGN) {
				next_lex();
				E();
				eq_type();
				prog.add_lex(Lex(LEX_ASSIGN));
			}
		} while (c_type == LEX_COMMA);
	}
}

void Parser::B()
{
	if (c_type == LEX_BEGIN) {
		do {
			next_lex();
			D();
		} while (c_type == LEX_SEMICOLON);

		do {
			int block = S();
			if (c_type == LEX_SEMICOLON)
				next_lex();
			else if (!block)
				throw_lex(curr_lex)
		} while (c_type != LEX_END);
		next_lex();
	} else
		throw_lex(curr_lex);
}

int Parser::S()
{
	Cycle C;
	int pl0, pl1, pl2, pl3, brk;
	int ret = 0;

	if (c_type == LEX_IF) {
		next_lex();
		if (c_type == LEX_LPAREN) {
			next_lex();
			E();
			eq_bool();
			pl2 = prog.get_rest();
			prog.blank();
			prog.add_lex(Lex(POLIZ_FGO));
			if (c_type == LEX_RPAREN) {
				next_lex();
				ret = S();
				if (c_type == LEX_SEMICOLON)
					next_lex();
				else if (ret == 0)
					throw_lex(curr_lex);
				pl3 = prog.get_rest();
				prog.blank();
				prog.add_lex(Lex(POLIZ_GO));
				prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), pl2);
				if (c_type == LEX_ELSE) {
					next_lex();
					ret = S();
					if (c_type == LEX_SEMICOLON)
						next_lex();
					else if (ret == 0)
						throw_lex(curr_lex);
				}
				prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), pl3);
			} else
				throw_lex(curr_lex);
		} else
			throw_lex(curr_lex);
		ret = 1;
	} else if (c_type == LEX_BREAK) {
		if (cycles.is_empty())
			throw "Break outside of cycle";
		Cycle C = cycles.pop();
		C.add_break(prog.get_rest());
		cycles.push(C);
		prog.add_lex(Lex(POLIZ_LABEL, 0));
		prog.add_lex(Lex(POLIZ_GO));
		next_lex();
	} else if ( c_type == LEX_WHILE ) {
		next_lex();
		if (c_type == LEX_LPAREN) {
			pl0 = prog.get_rest();
			next_lex();
			E();
			eq_bool();
			pl1 = prog.get_rest();
			prog.blank();
			prog.add_lex(Lex(POLIZ_FGO));
			if (c_type == LEX_RPAREN) {
				cycles.push(Cycle());
				next_lex();
				ret = S();
				if (c_type == LEX_SEMICOLON)
					next_lex();
				else if (ret == 0)
					throw_lex(curr_lex);
				prog.add_lex(Lex(POLIZ_LABEL, pl0));
				prog.add_lex(Lex(POLIZ_GO));
				prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), pl1);
				C = cycles.pop();
				while (brk = C.get_break())
					prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), brk);
			} else
				throw_lex(curr_lex);
		} else
			throw_lex(curr_lex);
		ret = 1;
	} else if ( c_type == LEX_FOR ) {
		next_lex();
		if (c_type == LEX_LPAREN) {
			cycles.push(Cycle());
			next_lex();
			E();
			//eq_bool();
			if (c_type == LEX_SEMICOLON)
				next_lex();
			else
				throw_lex(curr_lex);
			pl0 = prog.get_rest();
			E();
			eq_bool();
			if (c_type == LEX_SEMICOLON)
				next_lex();
			else
				throw_lex(curr_lex);
			pl1 = prog.get_rest();
			prog.blank();
			prog.add_lex(Lex(POLIZ_FGO));
			pl2 = prog.get_rest();
			prog.blank();
			prog.add_lex(Lex(POLIZ_GO));

			pl3 = prog.get_rest();
			E();
			//eq_bool();
			prog.add_lex(Lex(POLIZ_LABEL, pl0));
			prog.add_lex(Lex(POLIZ_GO));
			prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), pl2);
			if (c_type == LEX_RPAREN) {
				next_lex();
				ret = S();
				if (c_type == LEX_SEMICOLON)
					next_lex();
				else if (ret == 0)
					throw_lex(curr_lex);
				prog.add_lex(Lex (POLIZ_LABEL, pl3));
				prog.add_lex(Lex (POLIZ_GO));
				prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), pl1);
				C = cycles.pop();
				while (brk = C.get_break())
					prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), brk);
			} else
				throw_lex(curr_lex);
		} else
			throw_lex(curr_lex);
		ret = 1;
	} else if ( c_type == LEX_READ ) {
		next_lex();
		if ( c_type == LEX_LPAREN ) {
			next_lex();
			if ( c_type == LEX_ID ) {
				check_id_in_read();
				prog.add_lex(Lex ( POLIZ_ADDRESS, c_val));
				next_lex();
			} else
				throw_lex(curr_lex);
			if ( c_type == LEX_RPAREN ) {
				next_lex();
				prog.add_lex (Lex (LEX_READ));
			} else
				throw_lex(curr_lex);
		} else
			throw_lex(curr_lex);
	} else if ( c_type == LEX_WRITE ) {
		next_lex();
		if ( c_type == LEX_LPAREN ) {
			do {
				next_lex();
				E();
				prog.add_lex(Lex(LEX_WRITE));
			} while (c_type == LEX_COMMA);

			if (c_type == LEX_RPAREN)
				next_lex();
			else
				throw_lex(curr_lex);
		} else
			throw_lex(curr_lex);
	} else if (c_type == LEX_ID) {
		check_id();
		prog.add_lex(Lex(POLIZ_ADDRESS, c_val));
		next_lex();
		if (c_type == LEX_ASSIGN) {
			next_lex();
			E();
			eq_type();
			prog.add_lex(Lex(LEX_ASSIGN));
		} else
			throw_lex(curr_lex);
	} else if (c_type == LEX_GOTO) {
		next_lex();
		if (c_type == LEX_ID) {
			int addr;

			addr = save_label(prog.get_rest());
			prog.add_lex(Lex(POLIZ_LABEL, addr));
			prog.add_lex(Lex(POLIZ_GO));
			next_lex();
		} else
			throw_lex(curr_lex);
	} else if (c_type == LEX_LABEL) {
		int src;

		check_label();
		src = save_label(prog.get_rest());
		if (src)
			prog.add_lex(Lex(POLIZ_LABEL, prog.get_rest()), src);
		next_lex();
		ret = 1;
	} else {
		B();
		ret = 1;
	}
	return ret;
}

void Parser::E ()
{
	E11();
	if (c_type == LEX_OR) {
		st_lex.push(c_type);
		next_lex();
		E11();
		check_op();
	}
}

void Parser::E11 ()
{
	E12();
	if ( c_type == LEX_AND ) {
		st_lex.push(c_type);
		next_lex();
		E12();
		check_op();
	}
}

void Parser::E12 ()
{
	E1();
	if ( c_type == LEX_EQ || c_type == LEX_LS || c_type == LEX_GT ||
	     c_type == LEX_LE || c_type == LEX_GE || c_type == LEX_NE ) {
		st_lex.push(c_type);
		next_lex();
		E1();
		check_op();
	}
}

void Parser::E1 ()
{
	T();
	while (c_type == LEX_PLUS || c_type == LEX_MINUS) {
		st_lex.push(c_type);
		next_lex();
		T();
		check_op();
	}
}

void Parser::T ()
{
	F();
	while (c_type == LEX_TIMES || c_type == LEX_SLASH || c_type == LEX_PRCNT) {
		st_lex.push(c_type);
		next_lex();
		F();
		check_op();
	}
}

void Parser::F ()
{
	if (c_type == LEX_ID) {
		int id = c_val;

		check_id();
		next_lex();
		if (c_type == LEX_ASSIGN) {
			prog.add_lex(Lex(POLIZ_ADDRESS, id));
			next_lex();
			E();
			eq_type();
			prog.add_lex(Lex(LEX_ASSIGN));
			st_lex.push(TID[id].get_type());
		} else {
			prog.add_lex(Lex(LEX_ID, id));
		}
	} else if ( c_type == LEX_NUM ) {
		st_lex.push(LEX_INT);
		prog.add_lex(curr_lex);
		next_lex();
	} else if (c_type == LEX_STR) {
		st_lex.push(LEX_STRING);
		prog.add_lex(curr_lex);
		next_lex();
	} else if (c_type == LEX_TRUE) {
		st_lex.push(LEX_BOOL);
		prog.add_lex(Lex(LEX_TRUE, 1));
		next_lex();
	} else if (c_type == LEX_FALSE) {
		st_lex.push(LEX_BOOL);
		prog.add_lex(Lex(LEX_FALSE, 0));
		next_lex();
	} else if (c_type == LEX_NOT) {
		next_lex();
		F();
		check_not();
	} else if (c_type == LEX_MINUS) {
		next_lex();
		F();
		check_unary();
	} else if (c_type == LEX_LPAREN) {
		next_lex();
		E();
		if (c_type == LEX_RPAREN)
			next_lex();
		else
			throw_lex(curr_lex);
	} else
		throw_lex(curr_lex);
}

class Executer {
	Lex pc_el;
public:
	void execute(Poliz & poliz);
};

void Executer::execute(Poliz & poliz) {
	Stack < Arg , poliz_array_size > args;
	Arg a;
	int i, j;
	int index = 1, size = poliz.get_rest();

	while (index < size) {
		pc_el = poliz[index];

		if (execute_debug)
			cout << index << ": " << pc_el << endl;
		switch (pc_el.get_type()) {
		case LEX_TRUE:
		case LEX_FALSE:
		case LEX_NUM:
		case POLIZ_ADDRESS:
		case POLIZ_LABEL:
		case LEX_STR:
			args.push(pc_el.get_arg());
			break;
		case LEX_ID:
			i = pc_el.get_value();
			if (TID[i].get_assign()) {
				args.push(TID[i].get_arg());
				break;
			} else
				throw "POLIZ: indefinite identifier";
		case LEX_UNARY:
			i = args.pop().val;
			args.push(Arg(i * -1));
			break;
		case LEX_NOT:
			i = args.pop().val;
			args.push(Arg(!i));
			break;
		case LEX_OR:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i || j));
			break;
		case LEX_AND:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i && j));
			break;
		case POLIZ_GO:
			i = args.pop().val;
			if (i == 0 || index > size) {
				cout << index << endl;
				throw "POLIZ: indefinite GOTO label";
			}
			index = i - 1;
			break;
		case POLIZ_FGO:
			i = args.pop().val;
			j = args.pop().val;
			if (!j)
				index = i - 1;
			break;
		case LEX_WRITE:
			a = args.pop();
			if (a.type == LEX_STRING)
				cout << a.sval << endl;
			else if (a.type == LEX_INT || write_bool_as_int)
				cout << a.val << endl;
			else
				cout << (a.val ? "true" : "false") << endl;
			break;
		case LEX_READ:
			i = args.pop().val;
			if (TID[i].get_type() == LEX_INT) {
				int val;

				cout << "Input int value for " << TID[i].get_name() << endl;
				cin >> val;
				TID[i].set_value(val);
			} else if (TID[i].get_type() == LEX_STRING) {
				std::string str;

				cout << "Input string value for " << TID[i].get_name() << endl;
				cin >> str;
				TID[i].set_value(str);
			}
			else {
				string j;
				bool k;

				while(1) {
					cout << "Input boolean value (true or false) for ";
					cout << TID[i].get_name() << endl;
					cin >> j;
					if ( j != "true" && j != "false" ) {
						cout << "Error in input: true/false" << endl;
						continue;
					}
					k = (j == "true") ? true : false;
					break;
				}
				TID[i].set_value(k);
			}
			TID[i].set_assign();
			break;
		case LEX_PLUS:
			a = args.pop();
			if (a.type == LEX_STRING)
				args.push(Arg(args.pop().sval + a.sval));
			else
				args.push(Arg(args.pop().val + a.val));
			break;
		case LEX_TIMES:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i * j));
			break;
		case LEX_MINUS:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i - j));
			break;
		case LEX_SLASH:
			j = args.pop().val;
			i = args.pop().val;
			if ( !j )
				throw "POLIZ: divide by zero";
			args.push(Arg(i / j));
			break;
		case LEX_PRCNT:
			j = args.pop().val;
			i = args.pop().val;
			if ( !j )
				throw "POLIZ: divide by zero";
			args.push(Arg(i % j));
			break;
		case LEX_EQ:
			a = args.pop();
			if (a.type == LEX_STRING)
				args.push(Arg(args.pop().sval == a.sval));
			else
				args.push(Arg(args.pop().val == a.val));
			break;
		case LEX_GT:
			a = args.pop();
			if (a.type == LEX_STRING)
				args.push(Arg(args.pop().sval > a.sval));
			else
				args.push(Arg(args.pop().val > a.val));
			break;
		case LEX_LS:
			a = args.pop();
			if (a.type == LEX_STRING)
				args.push(Arg(args.pop().sval < a.sval));
			else
				args.push(Arg(args.pop().val < a.val));
			break;
		case LEX_GE:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i >= j));
			break;
		case LEX_LE:
			j = args.pop().val;
			i = args.pop().val;
			args.push(Arg(i <= j));
			break;
		case LEX_NE:
			a = args.pop();
			if (a.type == LEX_STRING)
				args.push(Arg(args.pop().sval != a.sval));
			else
				args.push(Arg(args.pop().val != a.val));

			break;
		case LEX_ASSIGN:
			a = args.pop();
			i = args.pop().val;
			if (execute_debug) {
				cout << "ID: " << i;
				cout << ", A.type: " << lexems[a.type];
				cout << ", TID.type: " << lexems[TID[i].get_type()];
				cout << ", TID.name: " << TID[i].get_name() << endl;
			}
			if (TID[i].get_type() == LEX_STRING) {
				if (a.type != LEX_STRING)
					throw "Argument type is not string!";
				TID[i].set_value(a.sval);
			} else if (TID[i].get_type() == LEX_INT) {
				if (a.type != LEX_INT)
					throw "Argument type is not int!";
				TID[i].set_value(a.val);
			} else {
				if (a.type != LEX_BOOL)
					throw "Argument type is not boolean!";
				TID[i].set_value(!!a.val);
			}
			TID[i].set_assign();
			args.push(TID[i].get_arg());
			break;
		default:
			throw "POLIZ: unexpected elem";
		}
		index++;
	}
	//cout << "Done!!!" << endl;
}

class Interpret {
	Parser pars;
	Executer Exec;
public:
	Interpret(const char * program) : pars(program) {};
	void interpret();
};

void Interpret::interpret() {
	pars.analyze();
	Exec.execute(pars.prog);
}

int main(int argc, char **argv)
{
	try {
		Interpret Intr(argv[1]);
		Intr.interpret();

		return 0;
	}

	catch (char c) {
		cout << "Unexpected symbol " << c << endl;
		return 1;
	}
	catch (Lex lex) {
		cout << "Unexpected lexeme" << endl;
		cout << lex;
		return 1;
	}
	catch (const char *src) {
		cout << src << endl;
		return 1;
	}

}
