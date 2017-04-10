#ifndef _RB_TREE_H_
#define _RB_TREE_H_
/***********************************************************

red/black tree utility
developed by wang hai ou
http://www.bloomsource.org/

any bug or questions , mail to whotnt@126.com

this code is free, you can use it for any purpose.

reference:
https://zh.wikipedia.org/wiki/%E7%BA%A2%E9%BB%91%E6%A0%91
http://en.literateprograms.org/Red-black_tree_(C)

how to use:
this code define the abstract action of a rbtree,
you can define your node struct, 
the first member of your node sturct MUST be rbnode, 
and define your own callback functions of 
compare two nodes, compare a value and a node, and swap two nodes.

***********************************************************/

#define RBTREE_ERR_EXIST              1

#define RBTREE_WALK_PRE_ORDER    1
#define RBTREE_WALK_IN_ORDER     2
#define RBTREE_WALK_POST_ORDER   3


#ifdef __cplusplus
extern "C"{
#endif


typedef struct _rbtree_node{
    int color;
    struct _rbtree_node* left;
    struct _rbtree_node* right;
    struct _rbtree_node* parent;
}rbnode;

/*
user defined function to compare value of two nodes

node1.value <  nod2.value , return -1
node1.value == nod2.value , return 0
node1.value >  nod2.value , return 1
*/
typedef int  (*rbtree_node_cmp )( rbnode* node1, rbnode* node2 );

/*
user defined function of compare a value and the value of a node

value <  node.value, return -1
value == node.value, return 0
value >  node.value, return 1
*/
typedef int  (*rbtree_value_cmp)( void* value, rbnode* node    );

/*
user defined function of swap the value and additional data of two nodes,
this function is used when delete node
*/
typedef void (*rbtree_node_swap)( rbnode* node1, rbnode* node2 );

/*
user defined function to proc a node
*/
typedef void (*rbtree_proc_node)( rbnode* node );

/*
user defined function get a value of a node
*/
typedef char* (*rbtree_node_value)( rbnode* node );


typedef struct{
    rbnode* root;
    int count;
    rbtree_node_cmp         node_cmp;
    rbtree_value_cmp        value_cmp;
    rbtree_node_swap        node_swap;
}rbtree;



/*
rbtree_init: init a rbtree

params:
tree          - pointer to a rbtree
node_cmp      - user defined function to compare two nodes by value
value_cmp     - user defined fucntion to compare a value and value of a node
swap          - user defined function to swap the value of two nodes
*/
void rbtree_init( rbtree* tree, rbtree_node_cmp node_cmp, rbtree_value_cmp value_cmp, rbtree_node_swap swap );


/*
rbtree_insert: insert a node to rbtree,

params:
tree          - pointer to a rbtree
node          - pointer to a node

return:
0             - insert success
none zero     - insert failed, value already exist, RBTREE_ERR_EXIST
*/
int  rbtree_insert( rbtree* tree, rbnode* node );


/*
rbtree_find : find the node with value val

params:
tree          - pointer to a rbtree
val           - pointer to value

return:
none null     - the pointer to the node
null          - the node with value val not exist
*/
rbnode* rbtree_find( rbtree* tree, void* val );


/*
rbtree_delete: delete the node with value val

params:
tree          - pointer to a rbtree
val           - pointer to value

return:
not null      - the pointer to node,
null          - the node with value val not exist


note:
if return value is not null, that means the node with value val
found in the tree, and has been delete from the tree,
you can free the node memory or throw it to the resource poll.

if return value is null, that means the node with value val
not found this the tree.
*/
rbnode* rbtree_delete( rbtree* tree, void* val );


/*
rbtree_verify: verity a rbtree, with the 5 rules of rbtree

params:
tree          - pointer to a rbtree

return:
0             - rbtree is ok
none zero     - rbtree is not ok
*/
int  rbtree_verify( rbtree* tree );


/*
rbtree_print: print a rbtree

params:
tree          - pointer to a rbtree
print         - user defined function to print node

*/
void rbtree_print( rbtree* tree, rbtree_proc_node print );


/*
rbtree_walk: walk the rbtree, and call the call back function with each node

params:
tree         - pointer to a rbtree
order        - order to walk the rbtree, ( pre_order, in_order, post_order )
cb           - call back function of each node
*/
void rbtree_walk( rbtree* tree, int order, rbtree_proc_node cb );


/*
rbtree_free: free the rbtree, and cll the callback function with each node

params:
tree         - pointer to a rbtree
cb           - call back function of each node
*/
void rbtree_free( rbtree* tree, rbtree_proc_node cb );


/*
rbtree_dot : generate a dot file of rbtree

params:
tree         - pointer to a rbtree
file         - dot file name
cb           - a call back funtion to print a node value

note:
graphviz is a tool generate computer graph, http://www.graphviz.org
you can install it with "yum install -y grphviz" or "apt-get install graphviz"

after you call this function, a dot file was create,
you can generate a png file of your rbtree with the following command:

dot -Tpng rbtree.dot  -o rbtree.png
*/
void rbtree_dot( rbtree* tree, char* file, rbtree_node_value cb );


#ifdef __cplusplus
}
#endif

#endif
