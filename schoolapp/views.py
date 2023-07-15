from django.shortcuts import get_object_or_404, render, HttpResponse, redirect, HttpResponseRedirect
from .models import *
from .serializer import SchoolSerializer, StudentSerializer
from rest_framework.viewsets import ModelViewSet

def index(request):
    return render(request, 'index.html')

class SchoolRetrieveDetails(ModelViewSet):
    queryset = School.objects.all()
    serializer_class = SchoolSerializer


class StudentRetrieveDetails(ModelViewSet):
    queryset = Student.objects.all()
    serializer_class = StudentSerializer


def sch_list(request):
    obj = School.objects.all()
    return render(request, 'school_list.html', {'obj':obj})

def stu_list(request):
    obj = Student.objects.all()
    return render(request, 'student_list.html', {'obj':obj})

def add_student(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        enrollment = request.POST.get('enrollment')
        school = request.POST.get('school')
        schid = School.objects.get(pk = school)
        query = Student.objects.create(name=name, enrollment=enrollment, schid=schid)
        query.save()
        return render(request, 'add_student.html')
    schools = School.objects.all()
    return render(request, "add_student.html", {'schools':schools})

def add_school(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        query = School.objects.create(name=name)
        query.save()
        return render(request, 'add_school.html')
    schools = School.objects.all()
    return render(request, "add_school.html", {'schools':schools})


def edit_student(request, pk):
    query = Student.objects.get(id=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        enrollment = request.POST.get('enrollment')
        school = request.POST.get('school')
        query = Student.objects.get(pk = pk)
        query.name = name
        query.enrollment = enrollment
        schoolnew = School.objects.get(pk = school)
        query.school = schoolnew
        query.save()
        return redirect('/app/stu-list/')
    schools = Student.objects.filter(pk = pk)
    schoolall = School.objects.all()
    return render(request, "edit_student.html", {'studata':schools, 'schools':schoolall})

def edit_school(request, pk):
    query = School.objects.get(id=pk)
    if request.method == 'POST':
        name = request.POST.get('name')
        query = School.objects.get(pk = pk)
        query.name = name
        query.save()
        return redirect('/app/sch-list/')
    schools = School.objects.filter(pk = pk)
    return render(request, "edit_school.html", {'studata':schools})

def delete_student(request, pk):
        query = Student.objects.get(id=pk)
        query.delete()
        return redirect ('/app/stu-list/')
   

def delete_school(request, pk):
        query = School.objects.get(id=pk)
        query.delete()
        return redirect ('/app/sch-list/')






from rest_framework.views import APIView
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated, AllowAny, IsAdminUser
from .serializer import LoginSerializer
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import BasicAuthentication


# obtain jwt tocken




class StudentAuthentication(APIView):
    authentication_classes = [JWTAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]
    permission_classes = [AllowAny]
    permission_classes = [IsAdminUser]

def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

#  obtain jwt token

class UserLogingAPI(APIView):
    def post(self, request, format=None):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.data.get('email')
        username = serializer.data.get('username')
        password = serializer.data.get('password')
        user = authenticate(email=email, password=password, username=username)
        if user is not None:
            token = get_tokens_for_user(user)
            return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['Email or Password, Username is not Valid']}}, status=status.HTTP_404_NOT_FOUND)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def allstudent(request):
    students = Student.objects.all()
    serilizer = StudentSerializer(students, many=True)
    return Response(serilizer.data)


@api_view(['POST', 'GET'])
@authentication_classes([BasicAuthentication])
def editstudent(request, pk):
    try:
        query = Student.objects.get(id=pk)
        serializer = StudentSerializer(query, data=request.data)
        if serializer.is_valid():
            serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Student.DoesNotExist:
        return Response({"error": "Student not found"}, status=status.HTTP_404_NOT_FOUND)
    
@api_view(['POST', 'GET'])
@authentication_classes([BasicAuthentication])
def retrievestudent(request, pk):
    try:
        query = Student.objects.get(id=pk)
        serializer = StudentSerializer(query)
        return Response(serializer.data, status=status.HTTP_200_OK)
    except Student.DoesNotExist:
        return Response({"error": "Student not found"}, status=status.HTTP_404_NOT_FOUND)

@api_view(['POST', 'GET'])
def createstudent(request):
    try:
        serializer = StudentSerializer(data = request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "Student has been created successfully"}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response ({"errormsg": "Something went wrong"})



















# new operation

from django.shortcuts import render, redirect
from .models import NewUser

from django.shortcuts import render, redirect
from django.http import JsonResponse

from .models import NewUser
from django.core.paginator import Paginator

# for authentication login page

from django.contrib.auth import authenticate, login
from django.contrib import messages

# for permission

from django.contrib.auth.decorators import permission_required
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.template.loader import render_to_string



def ajaxdata(request):
    try:
        users = NewUser.objects.all()

        # Filtering
        name = request.GET.get('name')
        city = request.GET.get('city')

        if name:
            users = users.filter(name__icontains=name)
        else:
            name = ""

        if city:
            users = users.filter(city__icontains=city)
        else:
            city = ""

        # Pagination
        paginator = Paginator(users, 2)  # Display 2 records per page initially
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Check if it's an AJAX request
        if request.is_ajax():
            html = render_to_string('partial_data.html', {'page_obj': page_obj})
            return JsonResponse({'html': html, 'has_next': page_obj.has_next()})

        context = {
            'page_obj': page_obj,
            'name': name,
            'city': city
        }
        return render(request, 'ajax_data.html', context)
    except Exception as e:
        messages.error(request, "Please login to access data.")
        return redirect('/app/')
    
def add_data(request):
    if request.method == 'POST':
        name = request.POST['name']
        email = request.POST['email']
        password = request.POST['password']
        state = request.POST['state']
        city = request.POST['city']
        gender = request.POST['gender']

        interests = request.POST.getlist('interests[]')
        print(interests,"...")
        interests_str = ','.join(interests)
        print(interests_str,"...")
        
        profile = NewUser.objects.create(
            name=name,
            email=email,
            state=state,
            password=password,
            city=city,
            gender=gender,
            interests = interests_str,

        )

        
        

        profile.interests = interests_str
        
        documents = request.POST.getlist('documents')
        # print(documents, 'DOOooooooo')
        for document_type in documents:
            Document.objects.create(
                user=profile,
                docname=document_type,
            )
            
        
        file = request.FILES.get('file')
        # print(file,"file...")
        if file:
            Document.objects.create(
                user=profile,
                docname ='Uploaded File',
                document=file,
            )
        
        return redirect('/app/add-data/')  # Redirect to a success page after form submission


    return render(request,"add_data.html")

@login_required
def all_data(request):
    try:
        users = NewUser.objects.all()

        # Filtering
        name = request.GET.get('name')
        city = request.GET.get('city')

        if name:
            users = users.filter(name__icontains=name)
        else:
            name = ""

        if city:
            users = users.filter(city__icontains=city)
        else:
            city = ""

        # Pagination

        paginator = Paginator(users, 10)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        context = {
            'page_obj': page_obj,
            'name': name,
            'city': city
        }
        return render(request, 'all_data.html', context)
    except Exception as e:
        messages.error(request, "Please login to access data.")
        return redirect('/app/')

@login_required
def update_data(request, id):

    user = get_object_or_404(NewUser, pk=id)

    if request.method == 'POST':
        # Update user data based on the submitted form
        user.name = request.POST.get('name')
        user.email = request.POST.get('email')
        user.city = request.POST.get('city')
        user.state = request.POST.get('state')
        user.gender = request.POST.get('gender')
        interests = request.POST.getlist('interests[]')
        print(interests,"...")
        interests_str = ','.join(interests)
        print(interests_str,"...")

        user.interests = interests_str
        user.save()

        return redirect('/app/all-data/')

    context = {
        'user': user
    }
    return render(request, 'update_data.html', context)

@login_required
def delete_data(request, id):
        user = NewUser.objects.get(pk=id)
        user.delete()
        return redirect ('/app/all-data/')


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None and user.is_superuser:
            login(request, user)
            return redirect('/app/all-data/')  # Redirect to the dashboard page
        else:
            messages.error(request, 'Invalid credentials or insufficient permissions.')
    
    return render(request, 'login.html')


# def logout_view(request):
#     if request.method == 'POST':
#         username = request.POST.get['username']
#         password = request.POST.password['password']
#         user = authenticate(request, username=username, password=password)
#         print(user, "USERRRRRRRRRR")
#         if user is not None and user.is_superuser:
#             logout(request)
#             return redirect('/app/login/')
#         else:
#             return redirect('/app/')

def logout_view(request):
    if request.method == 'POST':
        if request.user.is_authenticated and request.user.is_superuser:
            logout(request)
    return redirect('/app/login/')
