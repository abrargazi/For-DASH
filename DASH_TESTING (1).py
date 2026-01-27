from selenium import webdriver
from selenium.webdriver.edge.service import Service
from selenium.webdriver.common.by import By

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

import time
# from selenium.webdriver.chrome.service import Service //Import for Chrome

# Driver Setup

# Chrome Driver
# service_obj = Service()
# driver = webdriver.Chrome(service=service_obj)

# To Keep Browser Open Indefinitely
options = webdriver.EdgeOptions()
options.add_experimental_option("detach", True)

# Edge Driver
service_obj = Service()
driver = webdriver.Edge(options=options, service=service_obj)

# Browser Open and Access

driver.maximize_window()
#driver.minimize_window()

driver.get("http://localhost:5001")  # To open the browser and go to the link

# Click
driver.find_element(By.CLASS_NAME, "nav-link").click()
#
# Admin Login
driver.find_element(By.NAME, "username").send_keys("admin")
driver.find_element(By.NAME, "password").send_keys("admin123")
driver.find_element(By.CLASS_NAME, "btn-lg").click()

# Admin Send Notification

time.sleep(2)
driver.find_element(By.XPATH, "//button[normalize-space()='Send Notification']").click()

# Admin Send Notification -> Form FillUp
driver.find_element(By.ID, "notificationTitle").send_keys("Emergency")
driver.find_element(By.ID, "notificationMessage").send_keys("Hello")
driver.find_element(By.ID, "notificationType").send_keys("Road Block")
driver.find_element(By.ID, "notificationTarget").send_keys("General Users Only")

# time.sleep(5)
# Admin Send Notification -> Form FillUp -> Button

# driver.find_element(By.XPATH, "(//input[@type='button'])").click()
driver.execute_script("submitNotification();")


# # Admin Bulletin post
#
# time.sleep(2)
# # driver.find_element(By.XPATH, "//button[normalize-space()='createBulletinPost']").click()
# driver.find_element(By.XPATH, "//button[@onclick='createBulletinPost()']").click()
# # Admin Send Notification -> Form FillUp
# driver.find_element(By.ID, "bulletinTitle").send_keys("Bulletin")
# driver.find_element(By.ID, "bulletinType").send_keys("Warning")
# driver.find_element(By.ID, "bulletinPriority").send_keys("Normal")
# driver.find_element(By.ID, "bulletinContent").send_keys("Creating Bulletin Post")
#
# # time.sleep(5)
# # Admin Send Notification -> Form FillUp -> Button
#
# # driver.find_element(By.XPATH, "(//input[@type='button'])").click()
# driver.execute_script("submitBulletinPost();")

#
# # User Login
# driver.find_element(By.NAME, "username").send_keys("user1")
# driver.find_element(By.NAME, "password").send_keys("user123")
# driver.find_element(By.CLASS_NAME, "btn-lg").click()
#
# time.sleep(2)
# # Request Help -> Click
# driver.find_element(By.XPATH,"//button[@onclick='openHelpRequestModal()']").click()
# # driver.execute_script("openHelpRequestModal();")
# time.sleep(5)
#
# #user -> Request Help -> Form fillup
# driver.find_element(By.ID, "requestType").send_keys("Food")
# driver.find_element(By.ID, "urgencyLevel").send_keys("High")
# driver.find_element(By.ID, "description").send_keys("I need Food Here")
# #user -> Request Help -> Form fillup ->Button
# driver.find_element(By.XPATH,"//button[@onclick='submitHelpRequest()']").click()


# # Blood Donation Click
# time.sleep(5)
# driver.find_element(By.XPATH,"//button[@onclick='viewBloodBank()']").click()
# # Blood Donation -> Request Blood
# driver.find_element(By.XPATH,"//button[@onclick='openRequestBloodModal()']").click()
# # Blood Donation -> Request Blood -> Form Fillup
# driver.find_element(By.ID, "requestBloodType").send_keys("O+")
# driver.find_element(By.ID, "requestQuantity").send_keys("2 units")
# driver.find_element(By.ID, "requestUrgency").send_keys("High")
# driver.find_element(By.ID, "patientName").send_keys("Omi")
# driver.find_element(By.ID, "hospitalName").send_keys("United Medical Hospital")
# driver.find_element(By.ID, "hospitalName").send_keys("United Medical Hospital")
# driver.find_element(By.ID, "requestContactPhone").send_keys("01823395097")
# driver.find_element(By.ID, "requestDescription").send_keys("Please Help! Need Blood")
# time.sleep(3)
# #Blood Donation -> Request Blood -> Form Fillup ->  Button
# driver.find_element(By.XPATH,"//button[@onclick='submitBloodRequest()']").click()

#Rescue Login
driver.find_element(By.NAME, "username").send_keys("rescue1")
driver.find_element(By.NAME, "password").send_keys("rescue123")
driver.find_element(By.CLASS_NAME, "btn-lg").click()


time.sleep(2)
# # Rescue Create Mission
# driver.find_element(By.XPATH, "//button[@onclick='openMissionModal()']").click()

# # Rescue Create Mission -> Form FillUp
# driver.find_element(By.ID, "missionType").send_keys("Rescue Operation")
# driver.find_element(By.ID, "missionPriority").send_keys("High")
# driver.find_element(By.ID, "missionDescription").send_keys("Emergency! We Have to go")
# driver.find_element(By.ID, "missionLocation").send_keys("Banasree")
#
# time.sleep(2)
# # Rescue Create Mission -> Form FillUp -> Button
# driver.find_element(By.XPATH,"//button[@onclick='createMission()']").click()
# # driver.find_element(By.CLASS_NAME, "btn").click()

#
# # # Rescue donate blood
# driver.find_element(By.XPATH, "//button[@onclick='viewBloodBank()']").click()
# time.sleep(2)
# # Rescue donate blood -> Donate Blood
# driver.find_element(By.XPATH, "//button[@onclick='openDonateBloodModal()']").click()
#
# # Rescue donate blood -> Donate Blood -> Form FillUp
# driver.find_element(By.ID, "donateBloodType").send_keys("O+")
# driver.find_element(By.ID, "donateQuantity").send_keys("1 units")
# driver.find_element(By.ID, "donateContactPhone").send_keys("0140394097")
# driver.find_element(By.ID, "donateDescription").send_keys("I Will Donate unit Blood")
#
# time.sleep(2)
# # Rescue Create Mission -> Form FillUp -> Button
# driver.find_element(By.XPATH,"//button[@onclick='submitBloodDonation()']").click()
# # driver.find_element(By.CLASS_NAME, "btn").click()







