#include <iostream>
using namespace std;
//Singly linked list

// This is a program of Singly linked list using class

class node
{
public:
	int data;
	node* next;

	node(int value)
	{
		data = value;
		next = NULL;
	}
};

int findlength(node*& head)
{
	int length = 1;
	node* temp = head;
	if (head == NULL)
	{
		return 0;
	}
	else
	{
		while (temp->next != head)
		{
			temp = temp->next;
			length++;
		}
		return length;
	}
}

void insertattail(node*& head, int data)
{
	if (head == NULL)
	{
		node* newnode = new node(data);
		head = newnode;
		return;
	}
	else
	{
		node* temp = head;
		while (temp->next != NULL)
		{
			temp = temp->next;
		}
		temp->next = new node(data);
	}
}



void insertatpos(node*& head, int pos, int data)
{
	node* temp = head;
	node* temp2 = head;
	node* n = new node(data);
	int c = 1;

	if (pos<1 || pos>findlength(head))
	{
		cout << "Invalid position for insertion !\n";
	}

	while (c != pos - 1)
	{
		temp = temp->next;
		temp2 = temp2->next;
	}
	temp2 = temp->next;
	temp->next = n;
	n->next = temp2;
}

void display(node*& head)
{
	node* temp = head;
	if (head == NULL)
	{
		cout << "Linked list is empty !";
	}
	else
	{
		while (temp->next != NULL)
		{
			cout << temp->data << " -> ";
			temp = temp->next;
		}
		cout << temp->data << "\n";
	}
}



int deletefrompos(node*& head, int pos)
{
	node* temp = head;
	int c = 1;

	if (pos <= 1 || pos > findlength(head))
	{
		cout << "Invalid position for deletion !\n";
	}

	else
	{
		while (c != pos - 1)
		{
			temp = temp->next;
			c++;
		}
		node* deleted = temp->next;
		temp->next = temp->next->next;
		return deleted->data;
	}
}

void deletefromtail(node*& head)
{
	node* temp = head;

	if (head == NULL)
	{
		"Linked list is empty !\n";
	}
	else
	{
		while (temp->next->next != NULL)
		{
			temp = temp->next;
		}
		delete temp->next;
		temp->next = NULL;
	}
}

void modifyvalue(node*& head, int pos, int val)
{
	node* temp = head;
	int c = 1;
	if (pos < 1 || pos > findlength(head))
	{
		cout << "Invalid position for modification of value !\n";
	}
	else
	{
		while (c != pos)
		{
			temp = temp->next;
			c++;
		}
		temp->data = val;
	}
}


int main()
{
	cout << "Singly Linked list : \n\n";
	node* head = NULL;
	insertattail(head, 1);
	insertattail(head, 2);
	insertattail(head, 3);
	insertattail(head, 4);
	insertattail(head, 5);
	display(head);
	deletefrompos(head, 9);
	deletefrompos(head, 4);
	display(head);
	deletefromtail(head);
	display(head);
	insertatpos(head, 2, 9);
	display(head);
	cout << "Lenghth of Linked List : " << findlength(head) << "\n";

}

