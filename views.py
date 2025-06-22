from django.shortcuts import render,redirect
from .models import User
from django.contrib import messages
from django.utils.datastructures import MultiValueDictKeyError
import random
from django.contrib.auth import logout
import pickle
import os



# Create your views here.

import urllib.request
import urllib.parse

def sendSMS(user,otp,mobile):
    data =  urllib.parse.urlencode({'username':'Codebook','apikey': '56dbbdc9cea86b276f6c' , 'mobile': mobile,
    'message' : f'Hello {user}, your OTP for account activation is {otp}. This message is generated from https://www.codebook.in server. Thank you', 'senderid': 'CODEBK'})
    data = data.encode('utf-8')
    request = urllib.request.Request("https://smslogin.co/v3/api.php?")
    f = urllib.request.urlopen(request, data)
    return f.read()


def index(request):
    return render(request,'user/index.html')



def about(request):
    return render(request,'user/about.html')



def admin_login(request):
    if request.method == "POST":
        username = request.POST.get('name')
        password = request.POST.get('password')
        if username == 'admin' and password == 'admin':
            messages.success(request, 'Login Successful')
            return redirect('admin_dashboard')
        else:
            messages.error(request, 'Invalid details !')
            return redirect('admin_login')
    return render(request,'user/admin-login.html')



def contact(request):
    return render(request,'user/contact.html')




def otp(request):
    user_id = request.session['user_id']
    user = User.objects.get(user_id=user_id)
    if request.method == "POST":
        otp_entered = request.POST.get('otp')
        print(otp_entered)
        user_id = request.session['user_id']
        print(user_id)
        try:
            user = User.objects.get(user_id=user_id)
            if str(user.otp) == otp_entered:
                messages.success(request, 'OTP verification  and Registration is  Successfully!')
                user.status = "Verified"
                user.save()
                return redirect('user_login')
            else:
                messages.error(request, 'Invalid OTP entered')
                print("Invalid OTP entered")
                return redirect('otp')

        except User.DoesNotExist:
            messages.error(request, 'Invalid user')
            print("invalid user")
            return redirect('user_register')
    return render(request,'user/otp.html', {'user':user})





def services(request):
    return render(request,'user/service.html')


def user_login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        try:
            user = User.objects.get(user_email=email)   
            if user.user_password == password:
                request.session['user_id'] = user.user_id
                if user.status == 'Accepted':
                    messages.success(request, 'Login Successful')
                    return redirect('user_dashboard')
                elif user.status == 'Pending':
                    resp = sendSMS(user.user_name, user.otp, user.user_phone)
                    messages.info(request, 'Otp verification is compalsary otp is sent to ' + str(user.user_phone))
                    return redirect('otp')
                else:
                    messages.error(request, 'Your account is not approved yet.')
                    return redirect('user_login')
            else:
                messages.error(request, 'Invalid Login Details')
                return redirect('user_login')
        except User.DoesNotExist:
            messages.error(request, 'Invalid Login Details')
            return redirect('user_login')
    return render(request,'user/user-login.html')


def user_dashboard(request):
    return render(request,'user/user-dashboard.html')


def user_profile(request):
    user_id  = request.session['user_id']
    user = User.objects.get(pk= user_id)
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        try:
            profile = request.FILES['profile']
            user.user_profile = profile
        except MultiValueDictKeyError:
            profile = user.user_profile
        password = request.POST.get('password')
        location = request.POST.get('location')
        user.user_name = name
        user.user_email = email
        user.user_phone = phone
        user.user_password = password
        user.user_location = location
        user.save()
        messages.success(request , 'updated succesfully!')
        return redirect('user_profile')
    return render(request,'user/user-profile.html',{'user':user})





def generate_otp(length=4):
    otp = ''.join(random.choices('0123456789', k=length))
    return otp




def user_register(request):
    if request.method == "POST":
        name = request.POST.get('name')
        email = request.POST.get('email')
        phone = request.POST.get('phone')
        password = request.POST.get('password')
        location = request.POST.get('address')
        profile = request.FILES.get('profile')
        try:
            User.objects.get(user_email =   email)
            messages.info(request, 'Email Already Exists!')
            return redirect('user_register')
        except:
            otp = generate_otp()
            user = User.objects.create(user_name=name, user_email=email, user_phone=phone, user_profile=profile, user_password=password, user_location=location,otp=otp)
            print(user)
            resp = sendSMS(user.user_name, user.otp, user.user_phone)
            user_id_new = request.session['user_id'] = user.user_id
            print(user_id_new)
            return redirect('otp')
    return render(request,'user/user-register.html')





def user_logout(request):
    logout(request)
    return redirect('user_login')


def cyber_sec(request):
    prediction = None
    if request.method == 'POST':
        diff_srv_rate = float(request.POST['diff_srv_rate'])
        dst_host_srv_diff_host_rate = float(request.POST['dst_host_srv_diff_host_rate'])
        dst_host_same_src_port_rate = float(request.POST['dst_host_same_src_port_rate'])
        srv_count = float(request.POST['srv_count'])
        protocol_type = str(request.POST['protocol_type'])
        dst_host_count = float(request.POST['dst_host_count'])
        logged_in = str(request.POST['logged_in'])
        dst_bytes = float(request.POST['dst_bytes'])
        count = float(request.POST['count'])

        protocol_type_to_int = {'tcp': 0, 'udp': 0, 'icmp': 0}
        protocol_type_int = protocol_type_to_int.get(protocol_type, 0)
        
        model_path = os.path.join(os.path.dirname(__file__), 'rfc.pkl')

        with open(model_path, 'rb') as file:
            model = pickle.load(file)

        input_data = [[diff_srv_rate, dst_host_srv_diff_host_rate, dst_host_same_src_port_rate, srv_count, protocol_type_int, dst_host_count, logged_in, dst_bytes, count]]

        prediction =  model.predict(input_data)[0]
    return render(request,'user/cyber-security.html',{'prediction':prediction})
