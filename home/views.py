from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import logout, authenticate, login
from django.db.utils import IntegrityError
from django.contrib import messages
from django.views.decorators.cache import cache_control
from django.core.mail import send_mail, BadHeaderError, EmailMessage
from django.contrib.auth.forms import PasswordResetForm
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes, force_str
from django.contrib.sites.shortcuts import get_current_site 
from functools import reduce
from datetime import datetime
from home.shemas import *
import bcrypt
import json
#fimport MongoClientrrom pymongo import MongoClient
from .token import account_activation_token
import datetime 
from pymongo import MongoClient



def get_db():
    client = MongoClient("mongodb+srv://vikas05:VikasKushwaha123@cluster0.w4oeelf.mongodb.net/troven?retryWrites=true&w=majority")
    db = client["expensetracker"]
    return db

def get_collection(name):
    db = get_db()
    return db[name]
def get_activities_collection():
    db = get_db()
    return db["activities"] 
def log_password_reset_activity(email, action, success=True):
    db = get_db()
    collection = db["password_reset_logs"]  # Replace with your desired collection name

    log_entry = {
        "email": email,
        "action": action,
        "success": success,
        "timestamp": datetime.datetime.now()
    }

    try:
        collection.insert_one(log_entry)
    except Exception as e:
        print(f"Error logging password reset activity: {e}")

def add_new_group(request):
    try:
        grp_name = request.POST.get('group_name')
        mem_list = request.POST.get('member_ids')
        mem_list = list(map(int, json.loads(mem_list)))

        group_collection = get_collection('groups')
        group_membership_collection = get_collection('group_memberships')
        activity_collection = get_collection('activities')

        grp = {
            'group_name': grp_name,
            'status': 'ACTIVE',
            'date': datetime.now()
        }
        group_id = group_collection.insert_one(grp).inserted_id

        my_gm = {
            'user_id': request.user.id,
            'group_id': group_id
        }
        group_membership_collection.insert_one(my_gm)

        notifications = [
            {
                'user_id': m_id,
                'sender_id': request.user.id,
                'group_id': group_id,
                'message_type': 'GROUP_INVITE',
                'message': 'ACCEPT AND JOIN GROUP.',
                'status': 'PENDING',
                'date': datetime.now()
            }
            for m_id in mem_list if m_id != request.user.id
        ]
        activity_collection.insert_many(notifications)

        data = {
            'message': 'Group Invite sent.',
            'status': 'success'
        }

    except IntegrityError as e:
        data = {
            'message': 'Group invite failed due to ' + str(e),
            'status': 'failed'
        }

    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type='application/json')

def accept_reject_group_request(request):
    activity_id = int(request.POST.get('activity_id'))
    status = request.POST.get('status')
    group_id = int(request.POST.get('group_id'))

    group_membership_collection = get_collection('group_memberships')
    activity_collection = get_collection('activities')

    if group_membership_collection.find_one({'user_id': request.user.id, 'group_id': group_id}):
        activity_collection.update_one({'_id': activity_id}, {'$set': {'status': 'ACCEPTED'}})

        data = {
            'message': 'You are already in group.',
            'status': 'failed'
        }
    elif activity_collection.find_one({'_id': activity_id})['status'] != 'PENDING':
        data = {
            'message': 'Action already taken.',
            'status': 'failed'
        }
    else:
        try:
            if status == 'Accept':
                gm = {
                    'user_id': request.user.id,
                    'group_id': group_id
                }
                group_membership_collection.insert_one(gm)

                activity_collection.update_one({'_id': activity_id}, {'$set': {'status': 'ACCEPTED'}})

                data = {
                    'message': 'Accepted.',
                    'status': 'success'
                }
            else:
                activity_collection.update_one({'_id': activity_id}, {'$set': {'status': 'REJECTED'}})

                data = {
                    'message': 'Rejected',
                    'status': 'success'
                }

        except IntegrityError as e:
            data = {
                'message': 'Request Failed due to ' + str(e),
                'status': 'error'
            }
        
    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type='application/json')

def add_friend_expense(request):
    friend_id = int(request.POST.get('friend_id'))
    friend_expense_name = request.POST.get('friend_expense_name')
    total_amount = int(request.POST.get('total_amount'))
    member_payed_amount_dic = json.loads(request.POST.get('member_payed_amount_dic'))
    member_must_pay_amount_dic = json.loads(request.POST.get('member_must_pay_amount_dic'))
    split_type = request.POST.get('split_type')
    dt = request.POST.get('datetime')
    message = request.POST.get('message')
    
    friend_collection = get_collection('friends')
    bill_collection = get_collection('bills')
    activity_collection = get_collection('activities')
    settlement_collection = get_collection('settlements')

    try:
        friend_row = friend_collection.find_one({'user_id': request.user.id, 'friend_id': friend_id, 'status': 'ACTIVE'})
        if friend_row:
            d = datetime.strptime(dt, '%Y-%m-%dT%H:%M')
            group_id = friend_row['group_id']

            bill = {
                'bill_name': friend_expense_name,
                'group_id': group_id,
                'status': 'PENDING',
                'date': d,
                'amount': total_amount,
                'split_type': split_type
            }
            bill_id = bill_collection.insert_one(bill).inserted_id

            notification = {
                'user_id': friend_id,
                'sender_id': request.user.id,
                'group_id': group_id,
                'bill_id': bill_id,
                'message_type': 'EXPENSE',
                'message': message,
                'status': 'PENDING',
                'date': datetime.now()
            }
            activity_collection.insert_one(notification)

            if split_type == 'percentage':
                remains = 0
                for mem_id in member_must_pay_amount_dic:
                    amount = total_amount * (member_must_pay_amount_dic[mem_id] / 100)
                    member_must_pay_amount_dic[mem_id] = int(amount)
                    remains += amount - int(amount)
                    
                for mem_id in member_must_pay_amount_dic:
                    if remains == 0:
                        break
                    if member_must_pay_amount_dic[mem_id] != 0:
                        member_must_pay_amount_dic[mem_id] += 1
                        remains -= 1
                
            members = member_payed_amount_dic.keys()
            settles = []
            for member in members:
                paid, debt = get_paid_debts(member_payed_amount_dic[member], member_must_pay_amount_dic[member])
                s = {
                    'user_id': int(member),
                    'bill_id': bill_id,
                    'group_id': group_id,
                    'paid': paid,
                    'must_pay': member_must_pay_amount_dic[member],
                    'debt': debt
                }
                settles.append(s)
            settlement_collection.insert_many(settles)

            data = {
                'message': 'Expense sent to your friend for verification.',
                'status': 'success'
            }

        else:
            data = {
                'message': 'He\'s not your friend yet',
                'status': 'failed'
            }
    except IntegrityError as e:
        data = {
            'message': 'Expense sending failed due to ' + str(e),
            'status': 'failed'
        }
        
    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type='application/json')

def add_group_expense(request):
    group_id = int(request.POST.get('group_id'))
    expense_name = request.POST.get('expense_name')
    total_amount = int(request.POST.get('total_amount'))
    member_payed_amount_dic = json.loads(request.POST.get('member_payed_amount_dic'))
    member_must_pay_amount_dic = json.loads(request.POST.get('member_must_pay_amount_dic'))
    split_type = request.POST.get('split_type')
    dt = request.POST.get('datetime')
    message = request.POST.get('message')
    
    bill_collection = get_collection('bills')
    activity_collection = get_collection('activities')
    settlement_collection = get_collection('settlements')

    members = member_payed_amount_dic.keys()

    try:
        d = datetime.strptime(dt, '%Y-%m-%dT%H:%M')

        bill_status = 'PENDING'
        if len(members) == 1:
            bill_status = 'SETTLED'

        bill = {
            'bill_name': expense_name,
            'group_id': group_id,
            'status': bill_status,
            'date': d,
            'amount': total_amount,
            'split_type': split_type
        }
        bill_id = bill_collection.insert_one(bill).inserted_id
        
        activities = [
            {
                'user_id': int(mem),
                'sender_id': request.user.id,
                'group_id': group_id,
                'bill_id': bill_id,
                'message_type': 'EXPENSE',
                'message': message,
                'status': 'PENDING',
                'date': datetime.now()
            }
            for mem in members if int(mem) != request.user.id
        ]
        activity_collection.insert_many(activities)

        if split_type == 'percentage':
            remains = 0
            for mem_id in member_must_pay_amount_dic:
                amount = total_amount * (member_must_pay_amount_dic[mem_id] / 100)
                member_must_pay_amount_dic[mem_id] = int(amount)
                remains += amount - int(amount)
                
            for mem_id in member_must_pay_amount_dic:
                if remains == 0:
                    break
                if member_must_pay_amount_dic[mem_id] != 0:
                    member_must_pay_amount_dic[mem_id] += 1
                    remains -= 1
                
        settles = []
        for member in members:
            paid, debt = get_paid_debts(member_payed_amount_dic[member], member_must_pay_amount_dic[member])
            s = {
                'user_id': int(member),
                'bill_id': bill_id,
                'group_id': group_id,
                'paid': paid,
                'must_pay': member_must_pay_amount_dic[member],
                'debt': debt
            }
            settles.append(s)
        settlement_collection.insert_many(settles)

        data = {
            'message': 'Expense sent to your group members for verification.',
            'status': 'success'
        }
    except IntegrityError as e:
        data = {
            'message': 'Expense sending failed due to ' + str(e),
            'status': 'failed'
        }
        
    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type='application/json')


#
def accept_reject_group_expense_request(request):
    db = get_db()
    activity_id = int(request.POST.get('activity_id'))
    group_id = int(request.POST.get('group_id'))
    bill_id = int(request.POST.get('bill_id'))
    status = request.POST.get('status')

    expenses_collection = db["expenses"]
    activities_collection = db["activities"]

    # Check if the bill is already rejected
    bill = expenses_collection.find_one({"id": bill_id})
    if bill and bill.get('status') == 'REJECTED':
        activities_collection.update_one({"id": activity_id}, {"$set": {"status": "REJECTED"}})
        data = {
            'message': 'Expense already rejected by other members',
            'status': 'failed'
        }
    else:
        try:
            if status == 'Accept':
                activities_collection.update_one({"id": activity_id}, {"$set": {"status": "ACCEPTED"}})

                # Check if all have accepted the expense or not
                status_of_bill = activities_collection.find({"group_id": group_id, "bill_id": bill_id}).distinct("status")
                if len(status_of_bill) == 1 and status_of_bill[0] == 'ACCEPTED':
                    settlements = db["settlements"].find({"bill_id": bill_id})
                    
                    if is_bill_settled(settlements):
                        expenses_collection.update_one({"id": bill_id}, {"$set": {"status": "SETTLED"}})
                    else:
                        expenses_collection.update_one({"id": bill_id}, {"$set": {"status": "UNSETTLED"}})

                data = {
                    'message': 'Expense accepted',
                    'status': 'success'
                }
            else:
                activities_collection.update_one({"id": activity_id}, {"$set": {"status": "REJECTED"}})
                expenses_collection.update_one({"id": bill_id}, {"$set": {"status": "REJECTED"}})
                
                data = {
                    'message': 'Expense rejected',
                    'status': 'success'
                }
        except Exception as e:
            data = {
                'message': 'Expense ' + status + 'tion ' + 'failed due to ' + str(e),
                'status': 'failed'
            }
        
    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type="application/json")

def is_bill_settled(settlements):
    # Assuming settlements is a cursor from pymongo
    for settlement in settlements:
        if settlement['debt'] > 0:
            return False
    return True

def accept_reject_friend_expense_request(request):
    db = get_db()
    activity_id = int(request.POST.get('activity_id'))
    group_id = int(request.POST.get('group_id'))
    bill_id = int(request.POST.get('bill_id'))
    status = request.POST.get('status')

    activities_collection = db["activities"]
    expenses_collection = db["expenses"]
    settlements_collection = db["settlements"]

    try:
        if status == 'Accept':
            # Update activity status to ACCEPTED
            activities_collection.update_one({"id": activity_id}, {"$set": {"status": "ACCEPTED"}})

            # Fetch the bill and its settlements
            bill = expenses_collection.find_one({"id": bill_id})
            settlements = list(settlements_collection.find({"bill_id": bill_id}))

            # Check if the bill is settled
            if is_bill_settled(settlements):
                new_status = 'SETTLED'
            else:
                new_status = 'UNSETTLED'

            # Update bill status
            expenses_collection.update_one({"id": bill_id}, {"$set": {"status": new_status}})

            data = {
                'message': 'Expense accepted',
                'status': 'success'
            }
        else:
            # Update activity status to REJECTED
            activities_collection.update_one({"id": activity_id}, {"$set": {"status": "REJECTED"}})

            # Update bill status to REJECTED
            expenses_collection.update_one({"id": bill_id}, {"$set": {"status": "REJECTED"}})

            data = {
                'message': 'Expense rejected',
                'status': 'success'
            }
    except Exception as e:
        data = {
            'message': 'Expense ' + status + 'tion ' + 'failed due to ' + str(e),
            'status': 'failed'
        }
        
    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type="application/json")

def is_bill_settled(settlements):
    for settlement in settlements:
        if settlement['debt'] > 0:
            return False
    return True

#

def get_friend(request):
    db = get_db()
    users_collection = db["users"]
    friends_collection = db["friends"]
    settlements_collection = db["settlements"]
    groups_collection = db["groups"]

    friend_user_id = int(request.POST.get('friend_user_id'))

    friend = users_collection.find_one({"id": friend_user_id})
    
    if not friend:
        result = {
            'status': 'failed',
            'message': 'Friend not found'
        }
        json_data = json.dumps(result)
        return HttpResponse(json_data, content_type="application/json")

    group_membership = friends_collection.find_one({"user_id": request.user.id, "friend_id": friend_user_id})

    if not group_membership:
        result = {
            'status': 'failed',
            'message': 'Group membership not found'
        }
        json_data = json.dumps(result)
        return HttpResponse(json_data, content_type="application/json")

    current_group_id = group_membership['group_id']

    current_group = groups_collection.find_one({"id": current_group_id})

    if not current_group:
        result = {
            'status': 'failed',
            'message': 'Group not found'
        }
        json_data = json.dumps(result)
        return HttpResponse(json_data, content_type="application/json")

    group_members = friends_collection.find({"group_id": current_group_id})
    group_members_name = [users_collection.find_one({"id": member['user_id']})['username'] for member in group_members]

    settlements = settlements_collection.find({"user_id": request.user.id, "group_id": current_group_id})

    def myconverter(o):
        if isinstance(o, datetime):
            return o.__str__()

    result = {
        'status': 'success',
        'message': 'Group details fetched',
        'friend_user_id': friend_user_id,
        'friend_name': friend['username'],
        'group_status': current_group['status'],
        'group_date': current_group['date'],
        'total_members': len(group_members_name),
        'group_members_name': group_members_name,
        'settlements': list(settlements)
    }

    json_data = json.dumps(result, default=myconverter)
    return HttpResponse(json_data, content_type="application/json")

#
def get_group(request):
    db = get_db()
    groups_collection = db["groups"]
    group_memberships_collection = db["group_memberships"]
    settlements_collection = db["settlements"]
    users_collection = db["users"]

    group_id = int(request.POST.get('group_id'))

    current_group = groups_collection.find_one({"id": group_id})
    
    if not current_group:
        result = {
            'status': 'failed',
            'message': 'Group not found'
        }
        json_data = json.dumps(result)
        return HttpResponse(json_data, content_type="application/json")

    group_members = group_memberships_collection.find({"group_id": group_id})
    group_members_name = [users_collection.find_one({"id": member['user_id']})['username'] for member in group_members]

    settlements = settlements_collection.find({"user_id": request.user.id, "group_id": group_id})

    payers_list = [
        list(settlements_collection.find({"paid": {"$gt": "$must_pay"}, "group_id": group_id, "bill_id": settlement['bill_id']}).values('user_id', 'user_id__username'))
        for settlement in settlements
    ]

    def myconverter(o):
        if isinstance(o, datetime):
            return o.__str__()

    result = {
        'status': 'success',
        'message': 'Group details fetched',
        'group_id': group_id,
        'group_name': current_group['group_name'],
        'group_status': current_group['status'],
        'group_date': current_group['date'],
        'total_members': len(group_members_name),
        'group_members_name': group_members_name,
        'settlements': list(settlements),
        'payers_list': list(payers_list)
    }

    json_data = json.dumps(result, default=myconverter)
    return HttpResponse(json_data, content_type="application/json")
#
def settle_payment(request):
    db = get_db()
    bills_collection = db["bills"]
    settlements_collection = db["settlements"]

    bill_id = int(request.POST.get('bill_id'))
    payed_amount = int(request.POST.get('payed_amount'))
    category = request.POST.get('category')
    payer_id = int(request.POST.get('payer_id'))

    bill = bills_collection.find_one({"id": bill_id})
    if not bill:
        data = {
            'status': 'failed',
            'message': 'Bill not found'
        }
        json_data = json.dumps(data)
        return HttpResponse(json_data, content_type="application/json")

    settlement = settlements_collection.find_one({"user_id": request.user.id, "bill_id": bill_id})
    payers_settlement = settlements_collection.find_one({"user_id": payer_id, "bill_id": bill_id})

    if not settlement or not payers_settlement:
        data = {
            'status': 'failed',
            'message': 'Settlement not found'
        }
        json_data = json.dumps(data)
        return HttpResponse(json_data, content_type="application/json")

    if payed_amount > 0 and payed_amount <= settlement['debt']:
        settlements_collection.update_one(
            {"_id": settlement['_id']},
            {"$inc": {"paid": payed_amount, "debt": -payed_amount}}
        )

        settlements_collection.update_one(
            {"_id": payers_settlement['_id']},
            {"$inc": {"paid": -payed_amount}}
        )

        # Check if the bill is settled
        unsettled_debts = settlements_collection.find({"bill_id": bill_id, "debt": {"$gt": 0}})
        if unsettled_debts.count() == 0:
            bills_collection.update_one({"id": bill_id}, {"$set": {"status": "SETTLED"}})

        data = {
            'status': 'success',
            'message': 'Payment Successful.'
        }
    else:
        data = {
            'status': 'failed',
            'message': 'Payment failed due to invalid value'
        }

    json_data = json.dumps(data)
    return HttpResponse(json_data, content_type="application/json")

# Main views
def home(request):
    if request.user.is_authenticated:
        return redirect('dashboard')

    return render(request, 'home/home.html')

#
def sign_up_handler(request):
    if request.method == 'POST':
        db = get_db()
        users_collection = db["users"]

        name = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        cpassword = request.POST.get('confirmPassword')
        phone = request.POST.get('phone')

        try:
            # Check if user already exists with the same email
            if users_collection.find_one({"email": email}):
                raise IntegrityError("Email already exists")

            # Create the user document
            user = {
                "name": name,
                "email": email,
                "password": password,
                "phone": phone,
                "is_active": False
            }

            # Insert the user document into MongoDB
            users_collection.insert_one(user)

            current_site = get_current_site(request)
            mail_subject = 'Activation link has been sent to your email id'
            message = render_to_string('acc_active_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(str(user["_id"]))),
                'token': account_activation_token.make_token(user),
            })
            email = EmailMessage(
                mail_subject, message, to=[email]
            )
            email.send()

            data = {
                'message': 'success'
            }
        except IntegrityError as e:
            print(e)
            data = {
                'message': 'failed'
            }

        json_data = json.dumps(data)
        return HttpResponse(json_data, content_type="application/json")
    
    return HttpResponse('404 page not found')
def activate(request, uidb64, token):
    db = get_db()
    users_collection = db["users"]

    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = users_collection.find_one({"_id": uid})
        
        if user and account_activation_token.check_token(user, token):
            users_collection.update_one({"_id": uid}, {"$set": {"is_active": True}})
            return HttpResponse('Thank you for your email confirmation. Now you can login to your account.')
        else:
            return HttpResponse('Activation link is invalid!')
    
    except (TypeError, ValueError, OverflowError):
        return HttpResponse('Activation link is invalid!')
#
#
                
                
            #
        #json_data = json.dumps(data)
        #return HttpResponse(json_data, content_type="application/json")

    #return HttpResponse('404 page not found')

from home.helpers import generate_jwt
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def login_handler(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('userpassword')
        print(username,password)

        db = get_db()
        users_collection = db["users"]

        # Retrieve user document based on username
        user = users_collection.find_one({"username": username})
        print(user,"check user in db")

        if user:
            stored_password = user['passowrd']
            if stored_password==password:
                my_access_token=generate_jwt(username)
                user['_id']=str(user['_id'])
                user['message']='success'
                user['token']=my_access_token
                json_data=json.dumps(user)
                # return redirect('dashboard')

                return HttpResponse(json_data, content_type="application/json")
            else:
                json_data={"message":"failed"}
                return HttpResponse(json_data, content_type="application/json")

        json_data={"message":"user Not Found","status_code":400,"message":"failed"}
        json_data=json.dumps(json_data)
        return HttpResponse(json_data, content_type="application/json")

    return HttpResponse('404 page not found')
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def logout_handler(request):
    logout(request)
    return redirect('home')

#)
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def dashboard(request):
    if not request.user.is_authenticated:
        return redirect('home')

    db = get_db()

    if request.method == 'POST':
        request_motive = request.POST.get('request_motive')

        if request_motive == 'invite_friend':
            json_data = invite_friend(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'accept_reject_friend_request':
            json_data = accept_reject_friend_request(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'invite_for_new_group':
            json_data = add_new_group(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'accept_reject_group_request':
            json_data = accept_reject_group_request(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'add_friend_expense':
            json_data = add_friend_expense(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'add_group_expense':
            json_data = add_group_expense(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'accept_reject_group_expense_request':
            json_data = accept_reject_group_expense_request(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'accept_reject_friend_expense_request':
            json_data = accept_reject_friend_expense_request(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'get_group':
            json_data = get_group(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'get_friend':
            json_data = get_friend(request)
            return HttpResponse(json_data, content_type="application/json")

        elif request_motive == 'settle_payment':
            json_data = settle_payment(request)
            return HttpResponse(json_data, content_type="application/json")

    # All Groups List 
    groups_collection = db["groups"]
    groups_list = list(groups_collection.find({
        "members": request.user.id,
        "status": "ACTIVE"
    }, {"_id": 1, "group_name": 1}))

    # Friend invites
    activity_collection = db["activities"]


    friend_invites = list(activity_collection.find({
    #     "user_id": request.user.id,
    #     "message_type": "FRIEND_REQUEST",
    #     "status": "PENDING"
    # }, {"sender_id": 1
    }))

    # All Users who are not friends
    friends_collection = db["friends"]
    my_friends = list(friends_collection.find())

    not_friend_users = list(db["users"].find({}))

    # All my friends
    friends_list = list(friends_collection.find())

    # All my groups 
    my_groups = list(groups_collection.find())

    groups_members = {}
    for group in my_groups:
        group_id = group["_id"]
        group_members = list(db["group_membership"].find({
            "group_id": group_id
        }, {"user_id": 1, "user_id.username": 1}))
        groups_members[group_id] = group_members

    # Group invites
    group_invites = list(activity_collection.find())

    # Group expense verification notification
    group_expense_requests = list(activity_collection.find())

    all_settles = []
    for request in group_expense_requests:
        settle = db["settlements"].find_one({
        #     "user_id": request.user.id,
        #     "group_id": request["group_id"]["_id"],
        #     "bill_id": request["bill_id"]
        # }, {"paid": 1, "debt": 1, "must_pay": 1
            }
        )
        all_settles.append(settle)

    zipped_group_expense_requests = []
    if group_expense_requests:
        zipped_group_expense_requests = zip(group_expense_requests, all_settles)

    # Friend expense verification notification
    friend_expense_requests = list(activity_collection.find({
    #     "group_id.group_name": "FRIEND",
    #     "user_id": request.user.id,
    #     "message_type": "EXPENSE",
    #     "status": "PENDING"
    # }, {
    #     "_id": 1, "message": 1, "group_id": 1, "group_id.group_name": 1,
    #     "bill_id": 1, "date": 1, "sender_id": 1, "bill_id.bill_name": 1,
    #     "bill_id.amount": 1, "bill_id.split_type": 1, "bill_id.date": 1
    # 
    }))

    all_settles = []
    for request in friend_expense_requests:
        settle = db["settlements"].find_one({
        #     "user_id": request.user.id,
        #     "group_id": request["group_id"]["_id"],
        #     "bill_id": request["bill_id"]
        # }, {"paid": 1, "debt": 1, "must_pay": 1
            })
        all_settles.append(settle)

    zipped_friend_expense_requests = []
    if friend_expense_requests:
        zipped_friend_expense_requests = zip(friend_expense_requests, all_settles)

    # All my expenses which are unsettled
    unsettled_expenses = list(db["settlements"].find({
    #     "user_id": request.user.id,
    #     "bill_id.status": "UNSETTLED"
    # }, {
    #     "user_id": 1, "user_id.username": 1, "bill_id_id": 1, "paid": 1,
    #     "debt": 1, "must_pay": 1, "bill_id.bill_name": 1, "bill_id.amount": 1,
    #     "bill_id.split_type": 1, "bill_id.date": 1, "bill_id.status": 1,
    #     "group_id.group_name": 1, "group_id": 1
    
    }))

    for expense in unsettled_expenses:
        expense["lent"] = lent_amount(expense["paid"], expense["must_pay"], expense["debt"])
        if expense["group_id"]["group_name"] == "FRIEND":
            friend = friends_collection.find_one({
            #     "user_id": {"$ne": request.user.id},
            #     "group_id": expense["group_id"]
            # }, {"user_id.username": 1
                })
            expense["group_id"]["group_name"] = friend["user_id"]["username"]

    unsettled_expenses = [expense for expense in unsettled_expenses if expense["lent"] != 0 or expense["debt"] != 0]

    context = {
        'friends_list': friends_list,
        'groups_list': groups_list,
        'not_friend_users': not_friend_users,
        'friend_invites': friend_invites,
        'groups_members': json.dumps(groups_members),
        'group_invites': group_invites,
        'zipped_group_expense_requests': zipped_group_expense_requests,
        'zipped_friend_expense_requests': zipped_friend_expense_requests,
        'unsettled_expenses': unsettled_expenses
    }
    print(context,"my all dashboard data")
    return render(request, 'home/dashboard.html', context)


def lent_amount(paid, must_pay, debt):
    if debt != 0:
        return 0
    return paid - must_pay









    
#
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def password_reset_confirm(request, uidb64=None, token=None):
    assert uidb64 is not None and token is not None  # checked by URLconf
    try:
        uid = urlsafe_base64_decode(uidb64)
        user = CustomUser.objects.get(pk=uid)
    except Exception as e:
        user = None

    if user is not None:
        if request.method == 'POST':
            if default_token_generator.check_token(user, token):
                password1 = request.POST.get('new_password')
                password2 = request.POST.get('new_password_confirm')
                if password1 == password2 and len(password1) != 0:
                    user.set_password(password1)
                    user.save()
                    messages.success(request,
                                    'Password Changed! Login to Continue')
                    log_password_reset_activity(user.email, "Password reset successful")
                    return redirect('home')
                else:
                    messages.error(request,
                                    'Both Passwords Must Match. Please try again!'
                                    )
                    log_password_reset_activity(user.email, "Password reset failed: Passwords do not match", success=False)
                    return redirect('password_reset_confirm', uidb64=uidb64, token=token)
            else:
                messages.error(request,
                                'The reset password link is no longer valid. Try again!'
                                )
                log_password_reset_activity(user.email, "Password reset failed: Invalid token", success=False)
                return redirect('home')
        elif not default_token_generator.check_token(user, token):
            messages.error(request,
                            'The reset password link is no longer valid. Try again!'
                            )
            log_password_reset_activity(user.email, "Password reset failed: Token expired or invalid", success=False)
            return redirect('home')
        else:
            return render(request, 'home/confirm_password.html')
    else:
        messages.error(request,
                        'The reset password link is no longer valid. Try again!'
                        )
        log_password_reset_activity("Unknown user" if user is None else user.email, "Password reset failed: User not found", success=False)
        return redirect('home')
#
def password_reset_request(request):
    if request.method == "POST":
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = CustomUser.objects.filter(email=data)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': request.META['HTTP_HOST'],
                        'site_name': 'Your Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http' if request.is_secure() else 'https',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        email = EmailMessage(subject, email, to=[user.email])
                        email.send()
                        # MongoDB operation example
                        expenses_collection = get_expenses_collection()
                        # Example MongoDB operation: Insert document
                        expenses_collection.insert_one({
                            "email": user.email,
                            "subject": subject,
                            "message": "Password reset email sent"
                        })
                        data = {
                            'message': 'success'
                        }
                    except BadHeaderError:
                        return HttpResponse('Invalid header found.')

                    json_data = json.dumps(data)
                    return HttpResponse(json_data, content_type="application/json")
            else:
                data = {
                    'message': 'no_user_found'
                }
                json_data = json.dumps(data)
                return HttpResponse(json_data, content_type="application/json")

    return redirect('home')



#
@cache_control(no_cache=True, must_revalidate=True, no_store=True)
def add_friend(request):
    if not request.user.is_authenticated:
        return redirect('home')
    
    if request.method == 'POST' and request.POST.get('request_motive') == 'send_friend_request':
        # Example: Inviting a friend
        json_data = invite_friend(request)
        log_activity(request.user.username, "send_friend_request")
        return HttpResponse(json_data, content_type="application/json")

    if request.method == 'POST' and request.POST.get('request_motive') == 'accept_reject_friend_request':
        # Example: Accepting or rejecting a friend request
        json_data = accept_reject_friend_request(request)
        log_activity(request.user.username, "accept_reject_friend_request")
        return HttpResponse(json_data, content_type="application/json")

    # Example: Handling other activities like settling payments
    if request.method == 'POST' and request.POST.get('request_motive') == 'settle_payment':
        json_data = settle_payment(request)
        log_activity(request.user.username, "settle_payment")
        return HttpResponse(json_data, content_type="application/json")
    
    # Retrieve all users except the authenticated user and their current friends
    users_qs = CustomUser.objects.exclude(id=request.user.id)
    frd = Friend.objects.filter(Q(friend1=request.user) | Q(friend2=request.user)).values_list('friend1', 'friend2')
    friend_ids = [friend_id for sublist in frd for friend_id in sublist]

    users = {}
    for user in users_qs:
        if user.id not in friend_ids:
            users[user.id] = user.username

    # Retrieve friend requests and pending invites
    friend_requests = Activity.objects.filter(user_id=request.user, message_type='INVITE', status='PENDING', bill_id=None)
    pending_invites = Activity.objects.filter(sender_id=request.user, message_type='INVITE', status='PENDING', bill_id=None)
    
    # Retrieve current friends
    all_friends = []
    all_friends1 = Friend.objects.filter(friend1=request.user, status='ACTIVE')
    all_friends2 = Friend.objects.filter(friend2=request.user, status='ACTIVE')

    for friend in all_friends1:
        all_friends.append(friend.friend2)
    for friend in all_friends2:
        all_friends.append(friend.friend1)

    # Retrieve bills requests or verifications
    bills_requests = Activity.objects.select_related('bill_id').filter(user_id=request.user, message_type='EXPENSE', status='PENDING')

    context = {
        'users': users,
        'friend_requests': friend_requests,
        'pending_invites': pending_invites,
        'all_friends': all_friends,
        'bills_requests': bills_requests,
    }

    return render(request, 'home/add_friend.html', context)


def log_activity(username, action):
    db = get_db()
    collection = db["activities"]  # Assuming you have a collection named 'activities' for logging

    activity_entry = {
        "username": username,
        "action": action,
        "timestamp": datetime.datetime.now()
    }

    try:
        collection.insert_one(activity_entry)
    except Exception as e:
        print(f"Error logging activity: {e}")