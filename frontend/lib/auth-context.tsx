'use client'
import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { gql } from './graphql'
import type { User } from './mock'
type AuthContextValue={user:User|null;token:string|null;loading:boolean;login:(email:string,password:string)=>Promise<void>;signup:(username:string,email:string,password:string)=>Promise<void>;logout:()=>void}
const AuthContext=createContext<AuthContextValue|null>(null)
export function AuthProvider({children}:{children:React.ReactNode}){const [user,setUser]=useState<User|null>(null);const [token,setToken]=useState<string|null>(null);const [loading,setLoading]=useState(true)
 useEffect(()=>{const saved=localStorage.getItem('knot_token');if(saved){setToken(saved);gql<{me:User|null}>('query Me { me { id username email role createdAt posts { id } } }').then(d=>setUser(d.me||null)).catch(()=>{localStorage.removeItem('knot_token');setToken(null)}).finally(()=>setLoading(false))}else if(process.env.NEXT_PUBLIC_USE_MOCK!=='false'){setToken('mock-token');setUser({...({id:'u-admin',username:'alex',email:'alex@knot.social',role:'admin',createdAt:new Date().toISOString(),posts:[]} as User)});setLoading(false)}else setLoading(false)},[])
 const login=async(email:string,password:string)=>{const d=await gql<{login:{token:string;user:User}}>('mutation Login($email:String!,$password:String!){login(email:$email,password:$password){token user{id username email role createdAt posts{id}}}}',{email,password});localStorage.setItem('knot_token',d.login.token);setToken(d.login.token);setUser(d.login.user)}
 const signup=async(username:string,email:string,password:string)=>{const d=await gql<{signup:{token:string;user:User}}>('mutation Signup($username:String!,$email:String!,$password:String!){signup(username:$username,email:$email,password:$password){token user{id username email role createdAt posts{id}}}}',{username,email,password});localStorage.setItem('knot_token',d.signup.token);setToken(d.signup.token);setUser(d.signup.user)}
 const logout=()=>{localStorage.removeItem('knot_token');setUser(null);setToken(null)}
 const value=useMemo(()=>({user,token,loading,login,signup,logout}),[user,token,loading]);return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>}
export function useAuth(){const value=useContext(AuthContext);if(!value)throw new Error('useAuth must be used within AuthProvider');return value}
