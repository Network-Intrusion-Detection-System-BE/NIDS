from django.shortcuts import render
from django.http import HttpResponse, HttpResponseBadRequest

# Create your views here.

def processPCAP(request):
    return render(request, 'index.html')

# def scanPCAP(request):
#     return HttpResponse('Hello World')

def scanPCAP(request):
    if request.method == 'POST':
        if 'pcap_file' not in request.FILES:
            return HttpResponseBadRequest('No file uploaded!')

        pcap_file = request.FILES['pcap_file']  # Access the uploaded file object

        # Read the file content
        with pcap_file.open(mode='rb') as f:
            file_content = f.read()

        # Process the file content as needed (e.g., save it, analyze it)
        # ... your logic here ...

        return HttpResponse('File content processed successfully!')

    return render(request, 'upload_pcap.html')