#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rbtree.h"

#define RED    1
#define BLACK  2

static void rotate_left ( rbtree* tree, rbnode* node );
static void rotate_right( rbtree* tree, rbnode* node );

static void insert_case1( rbtree* tree, rbnode* node );
static void insert_case2( rbtree* tree, rbnode* node );
static void insert_case3( rbtree* tree, rbnode* node );
static void insert_case4( rbtree* tree, rbnode* node );
static void insert_case5( rbtree* tree, rbnode* node );

static void delete_case1( rbtree* tree, rbnode *n );
static void delete_case2( rbtree* tree, rbnode *n );
static void delete_case3( rbtree* tree, rbnode *n );
static void delete_case4( rbtree* tree, rbnode *n );
static void delete_case5( rbtree* tree, rbnode *n );
static void delete_case6( rbtree* tree, rbnode *n );

static int  node_black_walk( rbnode* n, int find, int count );
static void node_walk( rbnode* node, int order, rbtree_proc_node cb );


static int rbtree_path_black_count( rbnode* n );
static int rbtree_verify_rednode( rbnode* n );
static int verify_node( rbnode* n );
static void node_free( rbnode* node, rbtree_proc_node cb );





void rotate_left( rbtree* tree, rbnode* node )
{
    //printf( "roate left of node %d\n", node->value );
    
    rbnode* parent = node->parent;
    rbnode* child = node->right;
    
    int parent_flag = 0;
    
    if( parent )
    {
        if( node == parent->left )
            parent_flag = 'L';
        else
            parent_flag = 'R';
    }
    
    if( parent_flag )
    {
        if( parent_flag == 'L' )
            parent->left = child;
        else
            parent->right = child;
    }
    
    node->right = child->left;
    if( child->left )
        child->left->parent = node;
    node->parent = child;
    
    child->left = node;
    child->parent = parent;
    
    if( !parent )
        tree->root = child;
    
    
    return;
    
}

void rotate_right( rbtree* tree, rbnode* node )
{
    //printf( "roate right of node %d\n", node->value );
    
    rbnode* parent = node->parent;
    rbnode* child = node->left;
    
    int parent_flag = 0;
    
    if( parent )
    {
        if( node == parent->left )
            parent_flag = 'L';
        else
            parent_flag = 'R';
    }
    
    if( parent_flag )
    {
        if( parent_flag == 'L' )
            parent->left = child;
        else
            parent->right = child;
    }
    
    node->left = child->right;
    if( child->right )
        child->right->parent = node;
    node->parent = child;
    
    child->right = node;
    child->parent = parent;
    
    if( !parent )
        tree->root = child;
    
    
    return;
    
}


static rbnode* grandparent( rbnode *n ){
     return n->parent->parent;
}

static rbnode* uncle( rbnode *n ){
     if(n->parent == grandparent(n)->left)
         return grandparent (n)->right;
     else
         return grandparent (n)->left;
}


void rbtree_init( rbtree* tree, rbtree_node_cmp node_cmp, rbtree_value_cmp value_cmp, rbtree_node_swap swap )
{

    tree->root = NULL;
    tree->count = 0;
    tree->node_cmp = node_cmp;
    tree->value_cmp = value_cmp;
    tree->node_swap = swap;
    
}

void insert_case1( rbtree* tree, rbnode* node )
{
    if( node->parent == NULL )
        node->color = BLACK;
    else
        insert_case2( tree, node );
}

void insert_case2( rbtree* tree, rbnode* node )
{
    if( node->parent->color == BLACK )
        return;
    else
        insert_case3( tree, node );
}

void insert_case3( rbtree* tree, rbnode* node )
{
    if(uncle(node) != NULL && uncle (node)->color == RED) {
         node->parent->color = BLACK;
         uncle (node)->color = BLACK;
         grandparent (node)->color = RED;
         insert_case1( tree, grandparent(node));
    }
    else
         insert_case4 (tree, node);
}

void insert_case4( rbtree* tree, rbnode* n )
{

    if(n == n->parent->right && n->parent == grandparent(n)->left) {
    /*
                 G
                /
               P
                \
                 N
    */
        rotate_left( tree, n->parent);
        n = n->left;
    } else if(n == n->parent->left && n->parent == grandparent(n)->right) {
    /*
                 G
                  \
                   P
                  /
                 N
    */
        rotate_right( tree, n->parent);
        n = n->right;
    }
    insert_case5 (tree, n);
}


void insert_case5( rbtree* tree, rbnode* n )
{
    n->parent->color = BLACK;
    grandparent (n)->color = RED;
    if(n == n->parent->left && n->parent == grandparent(n)->left) {
        rotate_right( tree, grandparent(n));
    } else {
        /* Here, n == n->parent->right && n->parent == grandparent (n)->right */
        rotate_left( tree, grandparent(n));
    }
}



int binary_node_insert( rbtree* tree, rbnode* node, rbnode* newnode )
{
    int cmp;
    
    cmp = tree->node_cmp( newnode, node );
    if( cmp == 0 )
        return RBTREE_ERR_EXIST;
    
    if( cmp < 0 )
    {
        if( node->left == NULL )
        {
            node->left = newnode;
            newnode->color = RED;
            newnode->left  = NULL;
            newnode->right = NULL;
            newnode->parent = node;
            tree->count++;
            return 0;
        }
        else
            return binary_node_insert( tree, node->left, newnode );
    }
    else
    {
        if( node->right == NULL )
        {
            node->right = newnode;
            newnode->color = RED;
            newnode->left = NULL;
            newnode->right = NULL;
            newnode->parent = node;
            tree->count++;
            return 0;
        }
        else
            return binary_node_insert( tree, node->right, newnode );
    }
    
}

static rbnode* binary_find( rbtree* tree, rbnode* node, void* val )
{
    int cmp;
    
    cmp = tree->value_cmp( val, node );
    
    if( cmp == 0 )
        return node;
    
    if( cmp < 0 )
    {
        if( node->left == NULL )
            return NULL;
        else
            return binary_find( tree, node->left, val );
    }
    else
    {
        if( node->right == NULL )
            return NULL;
        else
            return binary_find( tree, node->right, val );
    }
    
}

rbnode* rbtree_find( rbtree* tree, void* val )
{
    if( tree->root == NULL )
        return NULL;
    
    return binary_find( tree, tree->root, val );
    
}

int  rbtree_insert( rbtree* tree, rbnode* node )
{
    int rc;
    
    if( tree->root == NULL )
    {
        node->color = BLACK;
        node->left  = NULL;
        node->right = NULL;
        node->parent = NULL;
        tree->root = node;
        tree->count ++;
        return 0;
    }
    
    rc = binary_node_insert( tree, tree->root, node );
    if( rc )
        return rc;
    
    insert_case1( tree, node );
    
    return 0;
    
}

static void print_node( rbtree* tree, rbnode* node, rbtree_proc_node print )
{
    print( node );
    if( node->left )
        print_node( tree, node->left, print );
    
    if( node->right )
        print_node( tree, node->right, print );

    
    
}

void rbtree_print( rbtree* tree, rbtree_proc_node print )
{
    
    if( tree->root == NULL )
    {
        printf( "rbtree empty!\n" );
        return ;
    }

    print_node( tree, tree->root, print );
    
    printf( "\n\n" );
    return;
    
}


int  rbtree_verify( rbtree* tree )
{
    int rc;
    
    if( !tree->root )
        return 0;
    
    if( tree->root->color != BLACK )
    {
        printf( "root node is not black!\n" );
        return 1;
    }
    
    rc = rbtree_verify_rednode( tree->root );
    if( rc )
        return 1;
    
    rc = verify_node( tree->root );
    if( rc )
        return rc;
    return 0;
    
}

int verify_node( rbnode* n )
{
    int cnt;
    int find = 0;
    int rc;
    
    cnt = rbtree_path_black_count( n );
    rc = node_black_walk( n, find, cnt );
    if( rc )
        return 1;

    if( n->left )
    {
        rc = verify_node( n->left );
        if( rc )
            return rc;
    }
    
    if( n->right )
    {
        rc = verify_node( n->right );
        if( rc )
            return rc;
            
    }
    
        
    
    return 0;
}


int node_black_walk( rbnode* n, int find, int count )
{
    int rc;
    
    if( !n )
    {
        if( find != count )
        {
            printf( "black node in path not equal!\n" );
            return 1;
        }
        return 0;
    }
    else
    {
        if( n->color == BLACK )
            find ++;
        rc = node_black_walk( n->left, find, count );
        if( rc )
            return rc;
        rc = node_black_walk( n->right, find, count );
        if( rc )
            return rc;
        
        return 0;
    }
    
    
    
}

// caculate how many black node in path to any leaf
int rbtree_path_black_count( rbnode* n )
{
    int cnt = 0;
    while( n )
    {
        if( n->color == BLACK )
            cnt++;
        n = n->left;
    }
    
    return cnt;
}

int rbtree_verify_rednode( rbnode* n )
{
    int rc;
    
    if( n->color == RED )
    {
        if(( n->left ) && n->left->color != BLACK  )
        {
            printf( "red node %p child is red!\n", n );
            return 1;
        }
            
        if(( n->right ) && n->right->color != BLACK  )
        {
            printf( "red node %p child is red!\n", n );
            return 1;
        }
    }
    
    
    if( n->left )
    {
        rc = rbtree_verify_rednode( n->left );
        if( rc ) 
            return rc;
    }
     
    if( n->right )
    {
        rc = rbtree_verify_rednode( n->right );
        if( rc )
            return rc;
    }
    
    return 0;
    
}

static inline rbnode* find_subtree_min( rbnode* node )
{
    while( node->left )
        node = node->left;
    
    return node;
}

static inline rbnode* find_subtree_max( rbnode* node )
{
    while( node->right )
        node = node->right;
    
    return node;
}

static inline rbnode* sibling( rbnode* node )
{
    return node == node->parent->left ? node->parent->right : node->parent->left;
}


static void replace_child( rbtree* tree, rbnode* n, rbnode* child )
{
    rbnode* parent;
    
    parent = n->parent;
    if( child )
        child->parent = parent;
    
    if( parent )
    {
        if( parent->left == n )
            parent->left = child;
        else
            parent->right = child;
    }
    else
    {
        tree->root = child;
        if( child )
            child->color = BLACK;
    }
}

static int node_color( rbnode* n )
{
    if( !n )
        return BLACK;
    else
        return n->color;
}


void delete_one_child( rbtree* tree, rbnode *n)
{
        rbnode *child = n->left != NULL ? n->left : n->right;
        
        if(n->color == BLACK){
                n->color = node_color( child );
                delete_case1 ( tree, n );
        }
        replace_child( tree, n, child);
        
}

void delete_case1( rbtree* tree, rbnode *n)
{
        if(n->parent != NULL)
                delete_case2 ( tree, n);
}

void delete_case2( rbtree* tree, rbnode *n)
{
        rbnode *s = sibling (n);
 
        if(s->color == RED){
                n->parent->color = RED;
                s->color = BLACK;
                if(n == n->parent->left)
                        rotate_left(tree, n->parent);
                else
                        rotate_right(tree, n->parent);
        } 
        delete_case3 (tree, n);
}

void delete_case3( rbtree* tree, rbnode *n)
{
        rbnode *s = sibling (n);
 
        if( (n->parent->color == BLACK)&&
            ( node_color( s ) == BLACK)&&
            ( node_color( s->left ) == BLACK)&&
            ( node_color( s->right ) == BLACK)) {
                s->color = RED;
                delete_case1(tree, n->parent);
        } else
                delete_case4 (tree, n);
}

void delete_case4( rbtree* tree, rbnode *n)
{
        rbnode *s = sibling (n);
 
        if( (n->parent->color == RED)&&
            ( node_color( s ) == BLACK)&&
            ( node_color( s->left ) == BLACK)&&
            ( node_color( s->right ) == BLACK))
        {
                s->color = RED;
                n->parent->color = BLACK;
        } else
                delete_case5 (tree, n);
}

void delete_case5( rbtree* tree, rbnode *n )
{
        rbnode *s = sibling (n);
 
        if(s->color == BLACK){ /* this if statement is trivial, 
due to Case 2(even though Case two changed the sibling to a sibling's child, 
the sibling's child can't be red, since no red parent can have a red child). */
// the following statements just force the red to be on the left of the left of the parent, 
// or right of the right, so case six will rotate correctly.
                if( (n == n->parent->left)&&
                    ( node_color( s->right ) == BLACK)&&
                    ( node_color( s->left ) == RED))
                { // this last test is trivial too due to cases 2-4.
                        s->color = RED;
                        s->left->color = BLACK;
                        rotate_right (tree, s);
                } else if(
                    (n == n->parent->right)&&
                    ( node_color( s->left ) == BLACK)&&
                    ( node_color( s->right ) == RED)) 
                {// this last test is trivial too due to cases 2-4.
                        s->color = RED;
                        s->right->color = BLACK;
                        rotate_left (tree, s);
                }
        }
        delete_case6 (tree, n);
}


void delete_case6( rbtree* tree, rbnode *n )
{
        rbnode *s = sibling (n);
 
        s->color = n->parent->color;
        n->parent->color = BLACK;
 
        if(n == n->parent->left){
                s->right->color = BLACK;
                rotate_left(tree, n->parent);
        } else {
                s->left->color = BLACK;
                rotate_right(tree, n->parent);
        }
}

rbnode* rbtree_delete( rbtree* tree, void* val )
{
    rbnode* node;
    rbnode* min;
    
    if( tree->root == NULL )
        return NULL;
    
    node = rbtree_find( tree, val );
    if( node == NULL )
        return NULL;
    
    
    if( node->left && node->right )
    {
        min = find_subtree_min( node->right );
        tree->node_swap( node, min );
        node = min;
    }
    
    delete_one_child( tree, node );
    tree->count --;
    
    return node;
    
}

void rbtree_walk( rbtree* tree, int order, rbtree_proc_node cb )
{
    switch( order )
    {
        case RBTREE_WALK_PRE_ORDER:
        case RBTREE_WALK_IN_ORDER:
        case RBTREE_WALK_POST_ORDER:
            break;
        
        default:
            order = RBTREE_WALK_IN_ORDER;
    }

    node_walk( tree->root, order, cb );
    
}

void node_walk( rbnode* node, int order, rbtree_proc_node cb )
{
    if( !node )
        return;

    switch( order )
    {
        case RBTREE_WALK_PRE_ORDER:
            cb( node );
            node_walk( node->left, order, cb );
            node_walk( node->right, order, cb );
            break;
        
        case RBTREE_WALK_IN_ORDER:
            node_walk( node->left, order, cb );
            cb( node );
            node_walk( node->right, order, cb );
            break;
        
        case RBTREE_WALK_POST_ORDER:
            node_walk( node->left, order, cb );
            node_walk( node->right, order, cb );
            cb( node );
            break;
    }
    
}


void node_free( rbnode* node, rbtree_proc_node cb )
{
    if( node->left )
        node_free( node->left, cb );
    
    if( node->right )
        node_free( node->right, cb );
    
    cb( node );
    
}


void rbtree_free( rbtree* tree, rbtree_proc_node cb )
{
    if( !tree->root )
        return;

    node_free( tree->root, cb );
    tree->root = NULL;
    tree->count = 0;
    
}

void node_dot( rbnode* node, FILE* f, rbtree_node_value cb )
{
    char left_name[30], right_name[30];
    rbnode *left, *right;
    
    left  = node->left;
    right = node->right;

    if( left )
    {
        snprintf( left_name, sizeof(left_name), "n_%p", left );
        fprintf( f, "%s[color=%s,fontcolor=white, style=filled, shape=circle, label=\"%s\"];\n", left_name, left->color == RED ? "red" : "black", cb( left ) );
    }
    else
    {   snprintf( left_name, sizeof(left_name), "n_%p_l", node );
        fprintf( f, "%s[color=black, fontcolor=white, style=filled, shape=box,label=\"nil\", width=0.3, height= 0.1];\n", left_name );
    }
    
    if( right )
    {
        snprintf( right_name, sizeof(left_name), "n_%p", right );
        fprintf( f, "%s[color=%s,fontcolor=white, style=filled, shape=circle, label=\"%s\"];\n", right_name, right->color == RED ? "red" : "black", cb( right ) );
    }
    else
    {
        snprintf( right_name, sizeof(left_name), "n_%p_r", node );
        fprintf( f, "%s[color=black, fontcolor=white, style=filled, shape=box,label=\"nil\", width=0.3, height= 0.1];\n", right_name );
    }
    
    fprintf( f, "n_%p -> { %s  %s };\n", node, left_name, right_name );
    
    if( left )
        node_dot( left, f, cb );
    
    if( right )
        node_dot( right, f, cb );
        
}

void rbtree_dot( rbtree* tree, char* file, rbtree_node_value cb )
{
    FILE* f;
    rbnode* node;
    
    f = fopen( file, "w" );
    if( !f )
        return;
    
    fprintf( f, "digraph rbtree{\n" );
    
    if( tree->root )
    {
        node= tree->root;
        fprintf( f, "n_%p[color=%s,fontcolor=white, style=filled, shape=circle, label=\"%s\"];\n", node, node->color == RED ? "red" : "black", cb( node ) );
        node_dot( tree->root, f, cb );
    }
    else
        fprintf( f, "nil[color=black, fontcolor=white, style=filled, shape=box, label=\"nil\"];\n" );
    
    fprintf( f, "}\n" );
    fclose( f );
    
    
}



