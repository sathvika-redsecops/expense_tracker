#
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class CustomUserSchema(BaseModel):
    username: str
    phone: str = '-'  # Default value

    class Config:
        orm_mode = True
class GroupSchema(BaseModel):
    group_name: str
    status: str = 'PENDING'
    date: datetime

    class Config:
        orm_mode = True
class GroupMembershipSchema(BaseModel):
    user_id: int
    group_id: int

    class Config:
        orm_mode = True
class BillSchema(BaseModel):
    bill_name: str
    group_id: int
    amount: int
    split_type: str = 'EQUAL'
    date: datetime
    status: str = 'PENDING'

    class Config:
        orm_mode = True
class SettlementSchema(BaseModel):
    user_id: int
    bill_id: int
    group_id: int
    paid: int
    must_pay: int = 0
    debt: int

    class Config:
        orm_mode = True
class ActivitySchema(BaseModel):
    user_id: int
    sender_id: int
    group_id: int
    bill_id: int
    message_type: str = '-'
    message: str = '-'
    status: str = 'PENDING'
    date: datetime

    class Config:
        orm_mode = True
class FriendSchema(BaseModel):
    user_id: int
    friend_id: int
    group_id: int
    status: str = 'PENDING'

    class Config:
        orm_mode = True